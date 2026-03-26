# Prismoire

> The official home of this repository is [Codeberg](https://codeberg.org/fimbulent/prismoire). Please file issues and pull requests there.

A trust-based community discussion platform. Each user sees a different facet of the same content graph, shaped by their position in the trust network.

> **Status:** Pre-alpha, work in progress. Not yet usable.

## Overview

Prismoire is a forum where content visibility is determined by trust relationships between users. Authors control who can see their posts via configurable trust thresholds. Trust propagates transitively through the social graph with multiplicative decay. Two users viewing the same thread may see different content by design.

## Tech Stack

Rust (Axum) backend, SvelteKit frontend, SQLite database, Passkey (WebAuthn) authentication.

## Development

Requires a Rust toolchain and Node.js 22 + pnpm. A [Nix](https://nixos.org/) flake is provided for a reproducible dev environment with all dependencies.

```sh
# With Nix:
nix develop    # or: direnv allow

# Install frontend dependencies:
pnpm --dir web install

# Build the frontend:
pnpm --dir web build

# Run the server (serves API + frontend):
cd server && cargo run
```

The server creates a SQLite database (`prismoire.db`) in the working directory on first run. Migrations are applied automatically at startup.

### Environment Variables

| Variable            | Description                        | Default                                        |
|---------------------|------------------------------------|------------------------------------------------|
| `PRISMOIRE_DB`        | Path to the SQLite database file       | `prismoire.db` (relative to working directory) |
| `PRISMOIRE_WEB_DIR`   | Path to the SvelteKit build output     | `web/build/` (relative to repo root)           |
| `PRISMOIRE_RP_ID`     | WebAuthn relying party ID (domain)     | `localhost`                                    |
| `PRISMOIRE_RP_ORIGIN` | WebAuthn relying party origin URL      | `http://localhost:3000`                        |

### Offline Query Checking (Nix / CI)

SQLx verifies queries at compile time. For builds without a live database, run `cargo sqlx prepare` in `server/` after changing any query or migration, then commit the generated `.sqlx/` directory. Set `SQLX_OFFLINE=true` (already configured in the Nix flake).

## License

[AGPL-3.0](LICENSE.md)
