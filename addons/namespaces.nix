{ pkgs, lib, ... }:
let
  namespaces = [
    "cert-manager"
    "juicefs-csi"
    "monitoring"
  ];
in
{
  # Regular addons
  addons = lib.listToAttrs (
    map (namespace: {
      name = "${namespace}-namespace";
      value = {
        apiVersion = "v1";
        kind = "Namespace";
        metadata = {
          name = namespace;
          labels = {
            "addonmanager.kubernetes.io/mode" = "Reconcile";
          };
        };
      };
    }) namespaces
  );
}