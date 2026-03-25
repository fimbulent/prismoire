# Prismoire

A trust-based community discussion platform. Each user sees a different facet of the same content graph, shaped by their position in the trust network.

> **Status:** Pre-alpha, work in progress. Not yet usable.

## Overview

Prismoire is a forum where content visibility is determined by trust relationships between users. Authors control who can see their posts via configurable trust thresholds. Trust propagates transitively through the social graph with multiplicative decay. Two users viewing the same thread may see different content by design.

## Tech Stack

Rust (Axum) backend, SvelteKit frontend, SQLite database, Passkey (WebAuthn) authentication.

## Development

Requires a Rust toolchain. A [Nix](https://nixos.org/) flake is provided for a reproducible dev environment.

```sh
# With Nix:
nix develop    # or: direnv allow

# Run the server:
cd server && cargo run
```

## License

[AGPL-3.0](LICENSE.md)
