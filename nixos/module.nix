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
        WorkingDirectory = "/var/lib/prismoire";
      };
    };

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
  };
}
