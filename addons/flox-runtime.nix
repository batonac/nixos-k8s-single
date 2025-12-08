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
    # NOTE: This is a template example. Replace the environment reference with your actual Flox environment.
    # The pod will fail to start until you provide a valid Flox environment reference.
    flox-example-pod = {
      apiVersion = "v1";
      kind = "Pod";
      metadata = {
        name = "flox-example";
        namespace = "flox-workloads";
        annotations = {
          # TODO: Replace with your actual Flox environment from FloxHub
          # Format: "floxhub/<org>/<environment-name>" or "floxhub/<user>/<environment-name>"
          # Example: "floxhub/myorg/hello-world" or "floxhub/john/nodejs-app"
          "flox.dev/environment" = "floxhub/YOUR_ORG/YOUR_ENVIRONMENT";
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
