{
  description = "Prismoire — trust-based community discussion platform";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      overlays = [
        rust-overlay.overlays.default
        (final: prev: {
          rustToolchain =
            let
              rust = prev.rust-bin;
            in
            if builtins.pathExists ./rust-toolchain.toml then
              rust.fromRustupToolchainFile ./rust-toolchain.toml
            else if builtins.pathExists ./rust-toolchain then
              rust.fromRustupToolchainFile ./rust-toolchain
            else
              rust.stable.latest.default.override {
                extensions = [ "rust-src" "rustfmt" ];
              };
          rustMinimal = prev.rust-bin.stable.latest.minimal;
        })
      ];
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEachSupportedSystem = f: nixpkgs.lib.genAttrs supportedSystems (system: f {
        pkgs = import nixpkgs { inherit overlays system; };
      });
    in
    {
      packages = forEachSupportedSystem ({ pkgs }: let
        lib = pkgs.lib;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = pkgs.rustMinimal;
          rustc = pkgs.rustMinimal;
        };

        # Filter the repo to only Rust-relevant files so the Nix store hash
        # doesn't change when non-Rust files (web/, docs/, etc.) are modified.
        # Allow all directories so nested module dirs (e.g. server/src/threads/)
        # are traversed; prune by file extension at the leaves.
        workspaceSrc = lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            type == "directory" ||
            builtins.match ".*\\.(rs|toml|lock|sql)$" path != null ||
            # sqlx offline query metadata (server/.sqlx/*.json) — required
            # when building with SQLX_OFFLINE=true in the Nix sandbox.
            builtins.match ".*/\\.sqlx/.*\\.json$" path != null;
        };

        server = rustPlatform.buildRustPackage {
          pname = "prismoire-server";
          version = "0.1.0";
          src = workspaceSrc;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "--package" "prismoire-server" ];
          nativeBuildInputs = with pkgs; [ pkg-config ];
          buildInputs = with pkgs; [ openssl ];
          SQLX_OFFLINE = "true";
          # Tests pull in web/src/lib/themes.ts via include_str! and need a
          # live-ish workspace; run them via `cargo test` in CI, not here.
          doCheck = false;
        };

        cli = rustPlatform.buildRustPackage {
          pname = "prismoire";
          version = "0.1.0";
          src = workspaceSrc;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "--package" "prismoire" ];
          nativeBuildInputs = with pkgs; [ pkg-config ];
          buildInputs = with pkgs; [ openssl ];
          doCheck = false;
        };

        web = pkgs.stdenv.mkDerivation (finalAttrs: {
          pname = "prismoire-web";
          version = "0.1.0";
          src = ./web;

          nativeBuildInputs = [
            pkgs.nodejs_22
            pkgs.pnpm_10
            pkgs.pnpmConfigHook
          ];

          CI = "true";

          pnpmDeps = pkgs.fetchPnpmDeps {
            inherit (finalAttrs) pname version src;
            pnpm = pkgs.pnpm_10;
            fetcherVersion = 3;
            hash = "sha256-gzk68cTb6aQjw6U2+xlWHH9yZjivv3PFfSNTIroYM2E=";
          };

          buildPhase = ''
            runHook preBuild
            pnpm build
            runHook postBuild
          '';

          # `installPhase` ships two things side by side in `$out`:
          #
          #   1. The SvelteKit adapter-node output (`build/`), copied
          #      to `$out` so `$out/index.js` is the entrypoint Node
          #      runs as `node ${cfg.webPackage}` from the systemd
          #      unit.
          #   2. A pruned production `node_modules/` next to it.
          #      adapter-node leaves runtime `dependencies`
          #      (`date-fns`, `marked`, `sanitize-html`) as bare
          #      ESM specifiers in the built server chunks, so Node's
          #      nearest-ancestor `node_modules` lookup has to find
          #      them at runtime — otherwise a page refresh that
          #      dynamically imports an un-seen route chunk fails
          #      with `ERR_MODULE_NOT_FOUND`. (docs/adapter-node.md
          #      calls this out: "The node_modules copy matters —
          #      adapter-node's build/index.js does requires against
          #      node_modules at runtime.")
          #
          # The prod `node_modules/` is materialized with a second
          # pnpm install into a staging directory, in `hoisted` node
          # linker mode so the result is a flat `node_modules` tree
          # with no symlinks back into the build sandbox's temporary
          # pnpm store. `--prod` drops `devDependencies` (Vite,
          # svelte-check, esbuild, @types/*, ...) which keeps the
          # store closure roughly an order of magnitude smaller than
          # shipping the build-time `node_modules` wholesale.
          installPhase = ''
            runHook preInstall

            cp -r build $out

            echo "Installing production node_modules (hoisted)"
            mkdir -p "$TMPDIR/prod-install"
            cp package.json pnpm-lock.yaml "$TMPDIR/prod-install/"
            pushd "$TMPDIR/prod-install"
            pnpm install \
              --offline \
              --prod \
              --ignore-scripts \
              --frozen-lockfile \
              --config.node-linker=hoisted
            popd
            cp -r "$TMPDIR/prod-install/node_modules" "$out/node_modules"

            runHook postInstall
          '';
        });
        bench = rustPlatform.buildRustPackage {
          pname = "prismoire-bench";
          version = "0.1.0";
          src = workspaceSrc;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "--package" "prismoire-bench" ];
          doCheck = false;
        };
      in {
        inherit server cli web bench;

        default = pkgs.symlinkJoin {
          name = "prismoire";
          paths = [ server cli ];
        };
      });

      nixosModules.default = import ./nixos/module.nix self;

      devShells = forEachSupportedSystem ({ pkgs }: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            openssl
            pkg-config
            cargo-watch
            rust-analyzer
            sqlite
            sqlx-cli
            nodejs_22
            nodePackages.pnpm
            mkcert
          ];
        };
      });
    };
}
