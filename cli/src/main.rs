use clap::{Parser, Subcommand};
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "prismoire", about = "Prismoire instance management CLI")]
struct Cli {
    /// Path to the TOML config file
    #[arg(long)]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage admin roles and inspect admin-visible state
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
}

#[derive(Subcommand)]
enum AdminAction {
    /// Grant admin role to a user
    Grant {
        /// User ID (UUID) to grant admin role
        user_id: String,
    },
    /// Revoke admin role from a user
    Revoke {
        /// User ID (UUID) to revoke admin role
        user_id: String,
    },
    /// Show CSP violation reports received from browsers.
    ///
    /// Reports are stored in the `csp_reports` table by the
    /// `/api/csp-report` endpoint (see server/src/csp_report.rs).
    /// Browser-extension noise is filtered at ingest, and rows older
    /// than 14 days are swept automatically.
    CspReports {
        /// Lookback window (e.g. `30m`, `24h`, `7d`). Default: last 24h.
        #[arg(long, default_value = "24h")]
        since: String,
        /// Maximum number of rows / groups to print.
        #[arg(long, default_value_t = 50)]
        limit: i64,
        /// Print individual reports instead of grouping by directive +
        /// blocked URI. Useful for investigating a single noisy entry.
        #[arg(long)]
        raw: bool,
    },
}

/// Open the SQLite database using the path from config.
async fn connect_db(
    config: &prismoire_config::Config,
) -> Result<SqlitePool, Box<dyn std::error::Error>> {
    let db_url = format!("sqlite:{}?mode=rw", config.server.database);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await?;
    Ok(pool)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = prismoire_config::load_config(cli.config.as_deref())?;

    match cli.command {
        Commands::Admin { action } => match action {
            AdminAction::Grant { user_id } => {
                let _ =
                    Uuid::parse_str(&user_id).map_err(|_| format!("invalid UUID: {user_id}"))?;
                let pool = connect_db(&config).await?;
                let result = sqlx::query(
                    "UPDATE users SET role = 'admin' WHERE id = ? AND status = 'active'",
                )
                .bind(&user_id)
                .execute(&pool)
                .await?;

                if result.rows_affected() == 0 {
                    eprintln!("error: no active user found with id {user_id}");
                    std::process::exit(1);
                }
                println!("granted admin role to user {user_id}");
            }
            AdminAction::Revoke { user_id } => {
                let _ =
                    Uuid::parse_str(&user_id).map_err(|_| format!("invalid UUID: {user_id}"))?;
                let pool = connect_db(&config).await?;
                let result =
                    sqlx::query("UPDATE users SET role = 'user' WHERE id = ? AND role = 'admin'")
                        .bind(&user_id)
                        .execute(&pool)
                        .await?;

                if result.rows_affected() == 0 {
                    eprintln!("error: no admin user found with id {user_id}");
                    std::process::exit(1);
                }
                println!("revoked admin role from user {user_id}");
            }
            AdminAction::CspReports { since, limit, raw } => {
                let since_seconds = parse_duration(&since)
                    .map_err(|e| format!("invalid --since value '{since}': {e}"))?;
                let pool = connect_db(&config).await?;
                show_csp_reports(&pool, since_seconds, limit, raw).await?;
            }
        },
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// CSP report listing
// ---------------------------------------------------------------------------

/// Parse a short duration string into seconds.
///
/// Accepts `<integer><unit>` where unit is one of `s`, `m`, `h`, `d`.
/// Intentionally minimal — this exists so operators can write `24h` or
/// `7d` without remembering a specific format, not to cover every edge
/// case a dedicated crate like `humantime` would.
fn parse_duration(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (num, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| "missing unit (expected s, m, h, or d)".to_string())?,
    );
    let n: i64 = num
        .parse()
        .map_err(|_| format!("not a valid integer: '{num}'"))?;
    let multiplier: i64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 60 * 60 * 24,
        other => return Err(format!("unknown unit '{other}' (expected s, m, h, or d)")),
    };
    Ok(n * multiplier)
}

/// Query the `csp_reports` table and print the results.
///
/// In the default (grouped) mode, rows are aggregated by
/// `(violated_directive, blocked_uri)` and printed with a count plus
/// first- and last-seen timestamps. This is the shape an operator
/// usually wants: one line per distinct violation, with recency.
///
/// In `--raw` mode, individual rows are printed newest first — useful
/// when one noisy group needs deeper inspection.
async fn show_csp_reports(
    pool: &SqlitePool,
    since_seconds: i64,
    limit: i64,
    raw: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // SQLite's `datetime('now', '-N seconds')` produces the UTC
    // threshold that the `received_at` column is compared against. The
    // column itself is stored as an ISO-8601 string in UTC, so string
    // comparison is correct.
    let threshold_modifier = format!("-{since_seconds} seconds");

    if raw {
        type RawRow = (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let rows: Vec<RawRow> = sqlx::query_as(
            "SELECT received_at, violated_directive, blocked_uri, document_uri, source_file \
             FROM csp_reports \
             WHERE received_at >= datetime('now', ?) \
             ORDER BY received_at DESC \
             LIMIT ?",
        )
        .bind(&threshold_modifier)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        if rows.is_empty() {
            println!("no CSP reports in the selected window");
            return Ok(());
        }

        println!(
            "{:<20}  {:<30}  {:<40}  DOCUMENT URI",
            "RECEIVED", "DIRECTIVE", "BLOCKED URI"
        );
        for (received_at, directive, blocked, document, _source) in rows {
            println!(
                "{:<20}  {:<30}  {:<40}  {}",
                received_at,
                directive.unwrap_or_else(|| "-".into()),
                blocked.unwrap_or_else(|| "-".into()),
                document.unwrap_or_else(|| "-".into()),
            );
        }
        return Ok(());
    }

    // Grouped view. `COALESCE` collapses NULLs so the GROUP BY keys are
    // stable across reporters that omit optional fields.
    let rows: Vec<(i64, String, String, String, String)> = sqlx::query_as(
        "SELECT \
            COUNT(*) AS n, \
            COALESCE(violated_directive, '(none)') AS directive, \
            COALESCE(blocked_uri, '(none)') AS blocked, \
            MIN(received_at) AS first_seen, \
            MAX(received_at) AS last_seen \
         FROM csp_reports \
         WHERE received_at >= datetime('now', ?) \
         GROUP BY directive, blocked \
         ORDER BY n DESC, last_seen DESC \
         LIMIT ?",
    )
    .bind(&threshold_modifier)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        println!("no CSP reports in the selected window");
        return Ok(());
    }

    let total: i64 = rows.iter().map(|(n, _, _, _, _)| *n).sum();
    println!(
        "{} reports across {} distinct (directive, blocked-uri) groups:\n",
        total,
        rows.len()
    );
    println!(
        "{:>6}  {:<30}  {:<40}  {:<20}  LAST SEEN",
        "COUNT", "DIRECTIVE", "BLOCKED URI", "FIRST SEEN"
    );
    for (n, directive, blocked, first_seen, last_seen) in rows {
        println!("{n:>6}  {directive:<30}  {blocked:<40}  {first_seen:<20}  {last_seen}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("30s"), Ok(30));
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("15m"), Ok(15 * 60));
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("24h"), Ok(24 * 60 * 60));
    }

    #[test]
    fn parse_duration_days() {
        assert_eq!(parse_duration("7d"), Ok(7 * 24 * 60 * 60));
    }

    #[test]
    fn parse_duration_trims_whitespace() {
        assert_eq!(parse_duration("  1h  "), Ok(60 * 60));
    }

    #[test]
    fn parse_duration_rejects_missing_unit() {
        assert!(parse_duration("42").is_err());
    }

    #[test]
    fn parse_duration_rejects_unknown_unit() {
        assert!(parse_duration("5y").is_err());
    }

    #[test]
    fn parse_duration_rejects_empty() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("   ").is_err());
    }

    #[test]
    fn parse_duration_rejects_non_numeric() {
        assert!(parse_duration("abc").is_err());
    }
}
