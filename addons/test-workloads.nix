{ pkgs, lib, ... }:
{
  # Regular addons
  addons = {
    alpine-test = {
      apiVersion = "v1";
      kind = "Pod";
      metadata = {
        name = "alpine-test";
        namespace = "default";
        labels = {
          "addonmanager.kubernetes.io/mode" = "Reconcile";
          app = "alpine-test";
        };
      };
      spec = {
        containers = [
          {
            name = "alpine";
            image = "alpine:latest";
            command = [
              "sleep"
              "3600"
            ];
            imagePullPolicy = "IfNotPresent";
            resources = {
              requests = {
                cpu = "100m";
                memory = "64Mi";
              };
            };
          }
        ];
        restartPolicy = "Always";
      };
    };

    nginx-deployment = {
      apiVersion = "apps/v1";
      kind = "Deployment";
      metadata = {
        name = "nginx";
        namespace = "default";
        labels = {
          "addonmanager.kubernetes.io/mode" = "Reconcile";
          app = "nginx";
        };
      };
      spec = {
        replicas = 1;
        selector = {
          matchLabels = {
            app = "nginx";
          };
        };
        template = {
          metadata = {
            labels = {
              app = "nginx";
            };
          };
          spec = {
            containers = [
              {
                name = "nginx";
                image = "nginx:1.25";
                imagePullPolicy = "IfNotPresent";
                ports = [
                  {
                    containerPort = 80;
                  }
                ];
              }
            ];
          };
        };
      };
    };

    nginx-service = {
      apiVersion = "v1";
      kind = "Service";
      metadata = {
        name = "nginx";
        namespace = "default";
        labels = {
          "addonmanager.kubernetes.io/mode" = "Reconcile";
          app = "nginx";
        };
      };
      spec = {
        selector = {
          app = "nginx";
        };
        ports = [
          {
            name = "http";
            port = 80;
            targetPort = 80;
          }
        ];
        type = "ClusterIP";
      };
    };
  };
}