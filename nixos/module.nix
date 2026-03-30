flake:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.prismoire;
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
        ExecStart = "${cfg.package}/bin/prismoire-server";
        User = "prismoire";
        Group = "prismoire";
        Restart = "on-failure";
        RestartSec = 5;
        StateDirectory = "prismoire";
        WorkingDirectory = cfg.dataDir;
        Environment = [
          "PRISMOIRE_PORT=${toString cfg.port}"
          "PRISMOIRE_DB=${cfg.dataDir}/prismoire.db"
          "PRISMOIRE_RP_ID=${cfg.rpId}"
          "PRISMOIRE_RP_ORIGIN=${cfg.rpOrigin}"
        ] ++ lib.optionals (cfg.setupTokenFile != null) [
          "PRISMOIRE_SETUP_TOKEN_FILE=${cfg.setupTokenFile}"
        ];
      };
    };

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
  };
}
