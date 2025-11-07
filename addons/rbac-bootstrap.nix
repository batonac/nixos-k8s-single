{ pkgs, lib, config, ... }:
{
  # Bootstrap addons (applied with cluster-admin rights at startup)
  bootstrapAddons = {
    # System component RBAC roles
    system-node-cr = {
      apiVersion = "rbac.authorization.k8s.io/v1";
      kind = "ClusterRole";
      metadata = {
        name = "system:node";
        labels."kubernetes.io/bootstrapping" = "rbac-defaults";
      };
      rules = [
        {
          apiGroups = [ "authentication.k8s.io" ];
          resources = [ "tokenreviews" ];
          verbs = [ "create" ];
        }
        {
          apiGroups = [ "authorization.k8s.io" ];
          resources = [ "localsubjectaccessreviews" "subjectaccessreviews" ];
          verbs = [ "create" ];
        }
        {
          apiGroups = [ "" ];
          resources = [ "services" ];
          verbs = [ "get" "list" "watch" ];
        }
        {
          apiGroups = [ "" ];
          resources = [ "nodes" ];
          verbs = [ "create" "get" "list" "watch" "patch" "update" ];
        }
        {
          apiGroups = [ "" ];
          resources = [ "nodes/status" ];
          verbs = [ "patch" "update" ];
        }
        {
          apiGroups = [ "" ];
          resources = [ "events" ];
          verbs = [ "create" "patch" "update" ];
        }
        {
          apiGroups = [ "" ];
          resources = [ "pods" ];
          verbs = [ "get" "list" "watch" "create" "delete" ];
        }
        {
          apiGroups = [ "" ];
          resources = [ "pods/status" ];
          verbs = [ "patch" "update" ];
        }
        {
          apiGroups = [ "" ];
          resources = [ "pods/eviction" ];
          verbs = [ "create" ];
        }
        {
          apiGroups = [ "" ];
          resources = [ "configmaps" "secrets" ];
          verbs = [ "get" "list" "watch" ];
        }
        {
          apiGroups = [ "" ];
          resources = [ "persistentvolumeclaims" "persistentvolumes" ];
          verbs = [ "get" ];
        }
        {
          apiGroups = [ "" ];
          resources = [ "endpoints" ];
          verbs = [ "get" ];
        }
        {
          apiGroups = [ "certificates.k8s.io" ];
          resources = [ "certificatesigningrequests" ];
          verbs = [ "create" "get" "list" "watch" ];
        }
        {
          apiGroups = [ "coordination.k8s.io" ];
          resources = [ "leases" ];
          verbs = [ "create" "delete" "get" "patch" "update" ];
        }
        {
          apiGroups = [ "storage.k8s.io" ];
          resources = [ "volumeattachments" "csidrivers" "csinodes" ];
          verbs = [ "get" "list" "watch" ];
        }
        {
          apiGroups = [ "" ];
          resources = [ "serviceaccounts/token" ];
          verbs = [ "create" ];
        }
        {
          apiGroups = [ "node.k8s.io" ];
          resources = [ "runtimeclasses" ];
          verbs = [ "get" "list" "watch" ];
        }
      ];
    };

    system-node-crb = {
      apiVersion = "rbac.authorization.k8s.io/v1";
      kind = "ClusterRoleBinding";
      metadata = {
        name = "system:node";
        labels."kubernetes.io/bootstrapping" = "rbac-defaults";
      };
      roleRef = {
        apiGroup = "rbac.authorization.k8s.io";
        kind = "ClusterRole";
        name = "system:node";
      };
      subjects = [{
        kind = "Group";
        name = "system:nodes";
      }];
    };

    # Empty ConfigMap to suppress controller-manager warning
    extension-apiserver-authentication-cm = {
      apiVersion = "v1";
      kind = "ConfigMap";
      metadata = {
        name = "extension-apiserver-authentication";
        namespace = "kube-system";
      };
      data = {
        "client-ca-file" = "";
        "requestheader-client-ca-file" = "";
      };
    };
  };
}
