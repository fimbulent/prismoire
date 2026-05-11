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

# Audit theme contrast in app.css and print proposed fixes (dry run)
theme-contrast:
    node scripts/fix-theme-contrast.mjs

# Apply minimum-deviation contrast fixes to app.css in place
theme-contrast-apply:
    node scripts/fix-theme-contrast.mjs --apply

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

# Regenerate the .sqlx/ offline query cache.
# `--tests --features test-auth` ensures the cache covers both
# `src/test_support.rs` (cfg-gated bypass handlers) and the integration
# tests under `tests/`, both of which CI builds with the feature on.
db-prepare:
    cd server && cargo sqlx prepare -- --tests --features test-auth

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

# Point git at the versioned pre-commit hook (one-time, per clone)
install-hooks:
    git config core.hooksPath scripts/git-hooks
    @echo "Hooks installed: git now runs scripts/git-hooks/*"

# Generate a random setup token for initial admin bootstrap
setup-token:
    @openssl rand -hex 32

# Grant admin role to a user
admin-grant user_id:
    cargo run -p prismoire -- admin grant {{user_id}}

# Revoke admin role from a user
admin-revoke user_id:
    cargo run -p prismoire -- admin revoke {{user_id}}

# Codepoint coverage for self-hosted prose fonts. Recovered from the union
# of the existing subsetted WOFF2s under web/static/fonts/*/. Roughly
# Google Fonts latin + latin-ext + vietnamese, plus a few extras (Latin
# Extended-C/D, currency, arrows, minus/division). Over-requesting is
# safe — pyftsubset silently skips codepoints the source font lacks.
font_unicodes := "U+0000,U+000D,U+0020-007E,U+00A0-024F,U+0259,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+1E00-1E9B,U+1E9D-1EFF,U+2000-200D,U+2010-2029,U+202F-2055,U+2057,U+205D,U+205F,U+2074,U+20A0-20AF,U+20B1-20B5,U+20B8-20BA,U+20BC-20BF,U+2113,U+2122,U+2191,U+2193,U+2212,U+2215,U+2C60-2C62,U+2C65-2C66,U+2C71,U+2C7C-2C7D,U+2C7F,U+A722-A725,U+A74E-A74F,U+A75A-A75B,U+A764-A765,U+A779-A787,U+A789,U+A7AD-A7AE,U+A7B3,U+A7B5,U+A7F2-A7F4,U+A7FF,U+FEFF,U+FFFD"

# Subset a TTF/OTF to Latin+latin-ext and re-encode as WOFF2 (Brotli).
# Preserves OpenType layout features and TrueType bytecode hints.
# Use after dropping a new font release in: replace the matching file under
# web/static/fonts/<family>/ with the output, then update @font-face in
# web/src/app.css if the weight/style coverage changed.
#
# Example:
#   just font-subset ~/Downloads/vollkorn-4.105/TTF/Vollkorn-Regular.ttf \
#       web/static/fonts/vollkorn/vollkorn.woff2
font-subset src dst:
    pyftsubset "{{src}}" \
        --flavor=woff2 \
        --layout-features='*' \
        --unicodes='{{font_unicodes}}' \
        --output-file="{{dst}}"