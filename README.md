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
just web-install

# Run frontend + backend in watch mode:
just dev

# Or build and run separately:
just web-build
just serve
```

The server creates a SQLite database (`prismoire.db`) in the working directory on first run. Migrations are applied automatically at startup.

On first boot, the server requires a setup token to create the initial admin account. See [Admin Bootstrap](#admin-bootstrap) below.

A [justfile](https://github.com/casey/just) provides all common development commands. Run `just -l` to see available recipes.

### Git Hooks

A pre-commit hook in `scripts/git-hooks/pre-commit` runs `cargo fmt`, regenerates `schema.sql` and the `.sqlx/` offline query cache when relevant files are staged, and enforces `cargo clippy -D warnings` and `cargo test`. Opt in once per clone:

```sh
just install-hooks
```

This points `core.hooksPath` at the versioned hooks directory, so future updates to the hook are picked up automatically on `git pull`.

### HTTPS for Local Development

WebAuthn (passkeys) requires a secure context. Generate locally-trusted TLS certs with `mkcert` (included in the Nix devShell):

```sh
just web-certs   # one-time setup
just dev         # serves over HTTPS
```

`just dev` uses `dev.toml`, which sets the WebAuthn origin to the Vite HTTPS dev server (`https://localhost:5173`).

### Configuration

The server reads configuration from a TOML file. The config file is resolved in order:

1. `--config <path>` CLI argument
2. `PRISMOIRE_CONFIG` environment variable
3. `prismoire.toml` in the working directory (if it exists)
4. Built-in defaults (suitable for local development)

With no config file, all defaults apply — no configuration is needed for `just serve`. `just dev` uses `dev.toml` to set the WebAuthn origin for the Vite dev server.

```toml
[server]
port = 3000                     # default: 3000
database = "prismoire.db"       # default: "prismoire.db"
trust_proxy_headers = false     # default: false — see note below
setup_token_file = "/run/secrets/prismoire-setup-token"  # required on first boot

[webauthn]
rp_id = "community.example.com"                    # default: "localhost"
rp_origin = "https://community.example.com"         # default: "http://localhost:3000"

[rate_limit]
ip_replenish_seconds = 1       # default: 1   — token refill interval for per-IP limit
ip_burst_size = 50             # default: 50  — max burst for per-IP limit
auth_replenish_seconds = 4     # default: 4   — refill interval for auth endpoints
auth_burst_size = 5            # default: 5   — max burst for auth endpoints
user_replenish_seconds = 1     # default: 1   — refill interval for per-user writes
user_burst_size = 20           # default: 20  — max burst for per-user writes
```

`trust_proxy_headers` controls where the per-IP rate limiter looks for the client IP:

- **Behind a trusted reverse proxy** (Caddy, nginx, etc.): set to `true`, otherwise every request appears to come from the proxy and the per-IP limit collapses to a single shared bucket.
- **Directly exposed to clients**: leave `false` (the default), otherwise a malicious client can forge `X-Forwarded-For` to bypass the limit.

Secrets use file indirection (`*_file` keys) — the server reads the file at startup and trims whitespace. Never put secrets directly in the config file.

### Admin Bootstrap

On a fresh instance with no admin account, the server requires a one-time setup token to create the first admin:

```sh
# Generate a setup token
just setup-token > /path/to/setup-token
```

Create a `prismoire.toml` (or pass `--config`):

```toml
[server]
setup_token_file = "/path/to/setup-token"
```

Then start the server:

```sh
just serve
```

Visit `/setup` in the browser, paste the token, choose a display name, and register a passkey. The admin account is created and the setup route is permanently disabled.

To grant or revoke admin role on an existing account:

```sh
just admin-grant <user-id>
just admin-revoke <user-id>

# Or with an explicit config file:
prismoire --config /path/to/config.toml admin grant <user-id>
```

### Inspecting CSP Violation Reports

Browsers post Content Security Policy violation reports to
`/api/csp-report`. The server filters browser-extension noise, stores
the rest in the `csp_reports` table, and sweeps rows older than 14
days automatically. To inspect recent reports from the CLI:

```sh
# Grouped view (default): aggregate by directive + blocked URI
prismoire admin csp-reports

# Custom lookback window and row limit
prismoire admin csp-reports --since 7d --limit 100

# Raw mode: print individual rows newest first
prismoire admin csp-reports --since 1h --raw
```

`--since` accepts `<integer><unit>` where unit is `s`, `m`, `h`, or
`d` (default: `24h`).

### Offline Query Checking (Nix / CI)

SQLx verifies queries at compile time. For builds without a live database, run `cargo sqlx prepare` in `server/` after changing any query or migration, then commit the generated `.sqlx/` directory. Set `SQLX_OFFLINE=true` (already configured in the Nix flake).

## NixOS Installation

A NixOS module is provided via flake. Add prismoire as a flake input and include the module:

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    prismoire.url = "git+https://codeberg.org/fimbulent/prismoire";
  };

  outputs = { nixpkgs, prismoire, ... }: {
    nixosConfigurations.my-server = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        prismoire.nixosModules.default
      ];
    };
  };
}
```

Then enable it in your `configuration.nix` file:

```nix
services.prismoire = {
  enable = true;
  port = 3000;     # internal Axum API port (loopback)
  webPort = 3001;  # internal SvelteKit Node port (loopback, default)
  rpId = "example.com";
  rpOrigin = "https://example.com";
  setupTokenFile = "/run/secrets/prismoire-setup-token"; # required on first boot

  # Required whenever the server sits behind a reverse proxy like the
  # Caddy block below. Leave false only if you plan to expose the Prismoire
  # API directly to clients without a proxy in front.
  trustProxyHeaders = true;
};

# Use something like Caddy to serve. Prismoire runs as two loopback
# processes — the Axum API on :3000 and the SvelteKit Node frontend on
# :3001 — so the reverse proxy fans out by path:
services.caddy = {
  enable = true;
  virtualHosts."example.com" = {
    extraConfig = ''
      encode zstd gzip

      # API + feeds go to the Axum server. API responses already carry
      # `Cache-Control: no-store`; do not override them here.
      @api path /api/*
      handle @api {
        reverse_proxy 127.0.0.1:3000
      }

      # Long-cache content-hashed SvelteKit bundles. These are
      # fingerprinted by the build so a year of caching is safe.
      handle /_app/immutable/* {
        header Cache-Control "public, max-age=31536000, immutable"
        reverse_proxy 127.0.0.1:3001
      }

      # Everything else (SSR HTML, static assets) goes to the Node
      # frontend. SSR responses set their own Cache-Control per page.
      handle {
        reverse_proxy 127.0.0.1:3001
      }
    '';
  };
};
networking.firewall.allowedTCPPorts = [ 80 443 ];
```

## License

[AGPL-3.0](LICENSE.md)
