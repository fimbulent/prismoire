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
    /// Manage admin roles
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
        },
    }

    Ok(())
}
