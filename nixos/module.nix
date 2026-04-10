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
      default = true;
      description = "Whether to open the firewall for the Prismoire server port.";
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = flake.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "The Prismoire server package to use.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.prismoire = {
      isSystemUser = true;
      group = "prismoire";
    };
    users.groups.prismoire = {};

    systemd.services.prismoire-server = {
      description = "Prismoire server";
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

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
  };
}
