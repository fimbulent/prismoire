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
web_dir = "web/build"           # default: relative to binary
setup_token_file = "/run/secrets/prismoire-setup-token"  # required on first boot

[webauthn]
rp_id = "community.example.com"                    # default: "localhost"
rp_origin = "https://community.example.com"         # default: "http://localhost:3000"
```

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
  port = 3000;
  rpId = "example.com";
  rpOrigin = "https://example.com";
  setupTokenFile = "/run/secrets/prismoire-setup-token"; # required on first boot
};

# Use something like Caddy to serve:
services.caddy = {
  enable = true;
  virtualHosts."example.com" = {
    extraConfig = ''
      @immutable path /_app/immutable/*
      header @immutable Cache-Control "public, max-age=31536000, immutable"
      @other not path /_app/immutable/*
      header @other Cache-Control "no-cache"
      reverse_proxy localhost:3000
    '';
  };
};
networking.firewall.allowedTCPPorts = [ 80 443 ];
```

## License

[AGPL-3.0](LICENSE.md)
