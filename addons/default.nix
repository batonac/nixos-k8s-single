{
  config,
  lib,
  pkgs,
  ...
}:
let
  # Define which addons to enable
  enabledAddons = [
    "rbac-bootstrap" # System RBAC bootstrapping
    "dns"
    "namespaces"
    "test-workloads"
    "rbac-bootstrap" # Add system RBAC bootstrapping
  ];

  # Import addon definitions
  addonModules = {
    dns = import ./dns.nix { inherit pkgs lib; };
    namespaces = import ./namespaces.nix { inherit pkgs lib; };
    test-workloads = import ./test-workloads.nix { inherit pkgs lib; };
    rbac-bootstrap = import ./rbac-bootstrap.nix { inherit pkgs lib config; };
  };

  # Get enabled addon definitions
  getEnabledAddons =
    addonType:
    lib.pipe enabledAddons [
      (map (name: addonModules.${name}.${addonType} or { }))
      (lib.foldr lib.recursiveUpdate { })
    ];

  bootstrapAddons = getEnabledAddons "bootstrapAddons";
  regularAddons = getEnabledAddons "addons";
  seedImages = lib.pipe enabledAddons [
    (map (name: addonModules.${name}.seedImages or [ ]))
    lib.flatten
  ];
in
{
  config = {
    # Seed docker images
    services.kubernetes.kubelet.seedDockerImages = seedImages;

    # Configure addon manager
    services.kubernetes.addonManager = {
      enable = true;
      bootstrapAddons = bootstrapAddons;
      addons = regularAddons;
    };
  };
}
