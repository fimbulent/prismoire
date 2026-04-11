flake:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.prismoire;

  configFormat = pkgs.formats.toml {};

  configAttrs = {
    server = {
      port = cfg.port;
      database = "${cfg.dataDir}/prismoire.db";
      trust_proxy_headers = cfg.trustProxyHeaders;
    } // lib.optionalAttrs (cfg.setupTokenFile != null) {
      setup_token_file = cfg.setupTokenFile;
    };
    webauthn = {
      rp_id = cfg.rpId;
      rp_origin = cfg.rpOrigin;
    };
    rate_limit = {
      ip_replenish_seconds = cfg.rateLimitIpReplenishSeconds;
      ip_burst_size = cfg.rateLimitIpBurstSize;
      auth_replenish_seconds = cfg.rateLimitAuthReplenishSeconds;
      auth_burst_size = cfg.rateLimitAuthBurstSize;
      user_replenish_seconds = cfg.rateLimitUserReplenishSeconds;
      user_burst_size = cfg.rateLimitUserBurstSize;
    };
  };

  configFile = configFormat.generate "prismoire.toml" configAttrs;

  # Wrapper that pre-supplies `--config` so operators can run e.g.
  # `prismoire admin csp-reports` on the host without remembering the
  # generated config path. The underlying binary still accepts an
  # explicit `--config` for ad-hoc use against a different config.
  prismoireCli = pkgs.writeShellScriptBin "prismoire" ''
    exec ${cfg.package}/bin/prismoire --config ${configFile} "$@"
  '';
in
{
  options.services.prismoire = {
    enable = lib.mkEnableOption "Prismoire server";

    port = lib.mkOption {
      type = lib.types.port;
      default = 3000;
      description = "Port the Prismoire server listens on.";
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/prismoire";
      description = "Directory for Prismoire state (database, etc.).";
    };

    rpId = lib.mkOption {
      type = lib.types.str;
      default = "localhost";
      description = "WebAuthn Relying Party ID (typically the domain name).";
    };

    rpOrigin = lib.mkOption {
      type = lib.types.str;
      default = "http://localhost:3000";
      description = "WebAuthn Relying Party origin URL.";
    };

    setupTokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Path to a file containing the one-time setup token for creating the
        initial admin account. Required on first boot; ignored after setup.
      '';
    };

    trustProxyHeaders = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether to trust `X-Forwarded-For`, `X-Real-IP`, and `Forwarded`
        headers when determining the client IP for per-IP rate limiting.
        Set this based on your deployment topology — the two cases are
        mutually exclusive:

        - **Behind a trusted reverse proxy** (Caddy, nginx, etc.) that
          overwrites these headers with the real peer IP: set to
          `true`. Otherwise every request appears to come from the
          proxy's single IP and the per-IP limit collapses onto one
          bucket shared by all clients.
        - **Directly exposed to clients** (no reverse proxy in front):
          leave at the `false` default. Otherwise a malicious client
          can forge these headers on every request and trivially
          bypass the per-IP limit.
      '';
    };

    rateLimitIpReplenishSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 1;
      description = "Seconds between token replenishment for per-IP rate limiting.";
    };

    rateLimitIpBurstSize = lib.mkOption {
      type = lib.types.ints.positive;
      default = 50;
      description = "Maximum burst size for per-IP rate limiting.";
    };

    rateLimitAuthReplenishSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 4;
      description = "Seconds between token replenishment for auth endpoint rate limiting.";
    };

    rateLimitAuthBurstSize = lib.mkOption {
      type = lib.types.ints.positive;
      default = 5;
      description = "Maximum burst size for auth endpoint rate limiting.";
    };

    rateLimitUserReplenishSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 1;
      description = "Seconds between token replenishment for per-user write rate limiting.";
    };

    rateLimitUserBurstSize = lib.mkOption {
      type = lib.types.ints.positive;
      default = 20;
      description = "Maximum burst size for per-user write rate limiting.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether to open the firewall for the Prismoire server port.

        Defaults to `false` because in the standard two-process
        deployment (Axum API + SvelteKit Node frontend) **both**
        services bind to loopback and only a reverse proxy
        (Caddy / nginx) is reachable from outside. The operator
        exposes the proxy's port(s) themselves — typically 80/443 —
        which is unrelated to `services.prismoire.port`.

        Set this to `true` only if you are exposing the Axum API
        directly to clients without a proxy in front (not
        recommended; also disables the per-IP rate limiting
        protection offered by `trustProxyHeaders`).
      '';
    };

    webPort = lib.mkOption {
      type = lib.types.port;
      default = 3001;
      description = ''
        Loopback port the SvelteKit Node (adapter-node) process
        listens on. Only the reverse proxy should reach this port;
        do not firewall it open.
      '';
    };

    webHost = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = ''
        Bind address for the SvelteKit Node process. Defaults to
        loopback, which is correct for a reverse-proxy deployment.
      '';
    };

    bodySizeLimit = lib.mkOption {
      type = lib.types.str;
      default = "1M";
      description = ''
        adapter-node `BODY_SIZE_LIMIT` — the maximum request body
        size the Node process will accept. Accepts a plain byte
        count or a human-readable suffix like `512K` / `1M`.
        Matches the adapter-node env var contract directly.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = flake.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "The Prismoire server package (Axum API binary).";
    };

    webPackage = lib.mkOption {
      type = lib.types.package;
      default = flake.packages.${pkgs.stdenv.hostPlatform.system}.web;
      description = ''
        The built SvelteKit frontend (`web/build` output of
        `adapter-node`). Must contain an `index.js` at its root.
      '';
    };

    nodePackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.nodejs_22;
      description = ''
        Node.js runtime used to execute the SvelteKit Node build.
        Pinned to match the version used to build `webPackage`.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.prismoire = {
      isSystemUser = true;
      group = "prismoire";
    };
    users.groups.prismoire = {};

    systemd.services.prismoire-server = {
      description = "Prismoire API server (Axum)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/prismoire-server --config ${configFile}";
        User = "prismoire";
        Group = "prismoire";
        Restart = "on-failure";
        RestartSec = 5;
        StateDirectory = "prismoire";
        WorkingDirectory = cfg.dataDir;
      };
    };

    # SvelteKit frontend as a separate Node process. Bound to loopback
    # and reached via the operator-provided reverse proxy (see README
    # for a Caddy example). Configured entirely through env vars
    # because that is adapter-node's native contract — see
    # `web/CLAUDE.md` ("Runtime configuration: env vars, not TOML")
    # for the rationale.
    #
    # Invariant: `ORIGIN` must equal `rpOrigin` so server-side fetches
    # from SvelteKit load functions carry an Origin that Axum's CSRF
    # middleware accepts. Drift here shows up as blanket 403s on every
    # non-GET server-side fetch.
    systemd.services.prismoire-web = {
      description = "Prismoire frontend (SvelteKit adapter-node)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" "prismoire-server.service" ];
      wants = [ "prismoire-server.service" ];
      environment = {
        HOST = cfg.webHost;
        PORT = toString cfg.webPort;
        ORIGIN = cfg.rpOrigin;
        API_URL = "http://127.0.0.1:${toString cfg.port}";
        BODY_SIZE_LIMIT = cfg.bodySizeLimit;
        NODE_ENV = "production";
      };
      serviceConfig = {
        ExecStart = "${cfg.nodePackage}/bin/node ${cfg.webPackage}";
        User = "prismoire";
        Group = "prismoire";
        Restart = "on-failure";
        RestartSec = 5;

        # Hardening: the web process is stateless and has no
        # filesystem needs beyond the read-only Nix store.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        PrivateTmp = true;
        PrivateDevices = true;
        RestrictSUIDSGID = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        # V8's JIT needs writable+executable pages, so
        # MemoryDenyWriteExecute is intentionally omitted.

        MemoryHigh = "256M";
        MemoryMax = "512M";
      };
    };

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    # Expose the `prismoire` admin CLI on PATH, pre-wired to the
    # generated config. Operators run it as the service user, e.g.
    # `sudo -u prismoire prismoire admin csp-reports`.
    environment.systemPackages = [ prismoireCli ];
  };
}
