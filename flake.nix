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
        workspaceSrc = lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let baseName = builtins.baseNameOf path; in
            # Keep only the Cargo workspace directory structure and Rust/SQL sources
            (type == "directory" && builtins.elem baseName [ "server" "cli" "src" "migrations" ]) ||
            builtins.match ".*\\.(rs|toml|lock|sql)$" path != null;
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
        };

        cli = rustPlatform.buildRustPackage {
          pname = "prismoire";
          version = "0.1.0";
          src = workspaceSrc;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "--package" "prismoire" ];
          nativeBuildInputs = with pkgs; [ pkg-config ];
          buildInputs = with pkgs; [ openssl ];
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
            hash = "sha256-Jqzi535o83rjHUuPcvt2y9wF0FgTqFvHScFNxx1h9tM=";
          };

          buildPhase = ''
            runHook preBuild
            pnpm build
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            cp -r build $out
            runHook postInstall
          '';
        });
      in {
        inherit server cli web;

        default = pkgs.symlinkJoin {
          name = "prismoire";
          paths = [ server cli ];
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postBuild = ''
            wrapProgram $out/bin/prismoire-server \
              --set PRISMOIRE_WEB_DIR "${web}"
          '';
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
