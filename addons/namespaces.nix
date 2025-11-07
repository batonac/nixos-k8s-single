{ pkgs, lib, ... }:
{
  bootstrapAddons = {};
  
  addons = {
    namespace-monitoring = {
      apiVersion = "v1";
      kind = "Namespace";
      metadata = {
        name = "monitoring";
        labels = {
          "addonmanager.kubernetes.io/mode" = "Reconcile";
          name = "monitoring";
        };
      };
    };
    
    namespace-cert-manager = {
      apiVersion = "v1";
      kind = "Namespace";
      metadata = {
        name = "cert-manager";
        labels = {
          "addonmanager.kubernetes.io/mode" = "Reconcile";
          name = "cert-manager";
        };
      };
    };
    
    namespace-juicefs-csi = {
      apiVersion = "v1";
      kind = "Namespace";
      metadata = {
        name = "juicefs-csi";
        labels = {
          "addonmanager.kubernetes.io/mode" = "Reconcile";
          name = "juicefs-csi";
        };
      };
    };
  };
  
  seedImages = [];
}