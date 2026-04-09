import? '.justfile.local'

# Run frontend + backend in watch mode
dev:
    #!/usr/bin/env bash
    export PRISMOIRE_CONFIG=dev.toml
    pnpm --dir web dev & VITE_PID=$!
    trap 'kill $VITE_PID 2>/dev/null; wait $VITE_PID 2>/dev/null' EXIT
    cargo watch -x 'run -p prismoire-server'

# Run the backend server once (no watch)
serve:
    cargo run -p prismoire-server

# Run the backend server with auto-reload on changes
watch:
    cargo watch -x 'run -p prismoire-server'

# Build the whole workspace
build:
    cargo build --workspace

# Install frontend dependencies
web-install:
    pnpm --dir web install

# Generate locally-trusted TLS certs for dev (one-time setup)
web-certs:
    mkdir -p web/certs
    mkcert -install
    mkcert -key-file web/certs/key.pem -cert-file web/certs/cert.pem localhost 127.0.0.1 ::1

# Run the frontend dev server standalone
web-dev:
    pnpm --dir web dev

# Build the frontend for production
web-build:
    pnpm --dir web build

# Typecheck the frontend
web-check:
    pnpm --dir web check

# Print the pnpm deps hash for flake.nix after changing JS dependencies
nix-hash:
    nix build .#packages.x86_64-linux.web.pnpmDeps 2>&1 || true
    @echo "If the hash above changed, update pnpmDeps.hash in flake.nix"

# Create the SQLite database
db-create:
    cd server && cargo sqlx database create

# Run pending database migrations
db-migrate:
    cd server && cargo sqlx migrate run

# Regenerate the .sqlx/ offline query cache
db-prepare:
    cd server && cargo sqlx prepare

# Dump the current schema (from migrations) to schema.sql
db-schema:
    #!/usr/bin/env bash
    set -euo pipefail
    tmp="$(mktemp)"
    trap 'rm -f "$tmp"' EXIT
    DATABASE_URL="sqlite://$tmp" cargo sqlx migrate run --source server/migrations
    sqlite3 "$tmp" .schema > schema.sql

# Delete the database and recreate from scratch
db-reset:
    rm -f server/prismoire.db server/prismoire.db-wal server/prismoire.db-shm
    cd server && cargo sqlx database create && cargo sqlx migrate run

# Generate a random setup token for initial admin bootstrap
setup-token:
    @openssl rand -hex 32

# Grant admin role to a user
admin-grant user_id:
    cargo run -p prismoire -- admin grant {{user_id}}

# Revoke admin role from a user
admin-revoke user_id:
    cargo run -p prismoire -- admin revoke {{user_id}}