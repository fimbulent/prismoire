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

A [justfile](https://github.com/casey/just) provides all common development commands. Run `just -l` to see available recipes.

### HTTPS for Local Development

WebAuthn (passkeys) requires a secure context. Generate locally-trusted TLS certs with `mkcert` (included in the Nix devShell):

```sh
just web-certs   # one-time setup
just dev         # automatically serves over HTTPS when certs exist
```

### Environment Variables

| Variable              | Description                          | Default                                        |
|-----------------------|--------------------------------------|------------------------------------------------|
| `PRISMOIRE_DB`        | Path to the SQLite database file     | `prismoire.db` (relative to working directory) |
| `PRISMOIRE_WEB_DIR`   | Path to the SvelteKit build output   | `web/build/` (relative to repo root)           |
| `PRISMOIRE_RP_ID`     | WebAuthn relying party ID (domain)   | `localhost`                                    |
| `PRISMOIRE_RP_ORIGIN` | WebAuthn relying party origin URL    | `http://localhost:3000`                        |

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
};

# Use something like Caddy to serve:
services.caddy = {
  enable = true;
  virtualHosts."example.com" = {
    extraConfig = ''
      reverse_proxy localhost:3000
    '';
  };
};
networking.firewall.allowedTCPPorts = [ 80 443 ];
```

## License

[AGPL-3.0](LICENSE.md)
