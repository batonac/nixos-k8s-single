{
  pkgs,
  lib,
  ...
}:
{
  # Bootstrap addons are applied first with cluster-admin rights
  bootstrapAddons = {
    # RuntimeClass for Flox Imageless Kubernetes
    flox-runtime-class = {
      apiVersion = "node.k8s.io/v1";
      kind = "RuntimeClass";
      metadata = {
        name = "flox";
      };
      handler = "flox";
      scheduling = {
        nodeSelector = {
          "flox.dev/runtime" = "enabled";
        };
      };
    };
  };

  # Regular addons are applied after bootstrap
  addons = {
    # Example Flox workload namespace
    flox-workloads-namespace = {
      apiVersion = "v1";
      kind = "Namespace";
      metadata = {
        name = "flox-workloads";
        labels = {
          name = "flox-workloads";
        };
      };
    };

    # Example Flox pod demonstrating Imageless Kubernetes
    flox-example-pod = {
      apiVersion = "v1";
      kind = "Pod";
      metadata = {
        name = "flox-example";
        namespace = "flox-workloads";
        annotations = {
          "flox.dev/environment" = "floxhub.example/hello-world";
        };
      };
      spec = {
        runtimeClassName = "flox";
        containers = [
          {
            name = "main";
            image = "registry.k8s.io/pause:3.9";
            command = [
              "echo"
              "Hello from Flox!"
            ];
            resources = {
              requests = {
                cpu = "100m";
                memory = "64Mi";
              };
              limits = {
                cpu = "200m";
                memory = "128Mi";
              };
            };
          }
        ];
        restartPolicy = "Never";
      };
    };
  };

  # No seed images needed for Flox - it manages environments directly
  seedImages = [ ];
}
