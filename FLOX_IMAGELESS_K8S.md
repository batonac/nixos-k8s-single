# Flox Imageless Kubernetes

This NixOS configuration includes support for [Flox Imageless Kubernetes](https://flox.dev/kubernetes/), which allows you to deploy workloads directly to Kubernetes using Flox environments instead of container images.

## Overview

Flox Imageless Kubernetes eliminates the need to build and manage container images. Instead, you define your application environment using Flox, and the runtime mounts that environment directly into your pods.

### Benefits

- **No Image Builds**: Skip the Docker/container image build process entirely
- **Reproducible Environments**: Flox lockfiles ensure consistent environments across development, testing, and production
- **Faster Deployments**: No need to push/pull large container images
- **Simplified Workflow**: Define your environment once, use it everywhere

## Architecture Changes

This configuration has been updated from CRI-O to containerd to support Flox:

- **Container Runtime**: containerd (replacing CRI-O)
- **Storage Driver**: OverlayFS on ext4 filesystem (replacing btrfs)
- **Runtime Shim**: containerd-shim-flox-v2 for Flox environment support
- **RuntimeClass**: `flox` RuntimeClass for scheduling Flox workloads

## Installation

The Flox runtime shim is automatically installed via the `install-flox-shim` systemd service, which:

1. Creates a Flox environment at `/var/lib/flox/containerd-shim`
2. Installs the `containerd-shim-flox` package
3. Symlinks the shim to `/usr/local/bin/containerd-shim-flox-v2`

### Manual Installation

If you need to manually install or reinstall the shim:

```bash
# As root
sudo systemctl restart install-flox-shim
```

## Node Labeling

For Flox pods to be scheduled correctly, nodes must be labeled with `flox.dev/runtime=enabled`:

```bash
# Label your node(s)
kubectl label node <node-name> flox.dev/runtime=enabled

# Verify the label
kubectl get nodes --show-labels | grep flox
```

## Using Flox Imageless Kubernetes

### 1. Create a Flox Environment

First, create a Flox environment for your application:

```bash
mkdir my-app
cd my-app
flox init

# Install packages
flox install nodejs npm

# Add environment variables and scripts as needed
flox edit
```

### 2. Publish to FloxHub

Publish your environment to FloxHub (or your private registry):

```bash
flox publish floxhub/<your-org>/<environment-name>
```

### 3. Deploy to Kubernetes

Create a pod/deployment that uses the Flox runtime:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: default
  annotations:
    # Reference your Flox environment
    flox.dev/environment: "floxhub/<your-org>/<environment-name>"
spec:
  # Use the flox RuntimeClass
  runtimeClassName: flox
  containers:
  - name: app
    # A minimal pause image - Flox provides the actual environment
    image: registry.k8s.io/pause:3.9
    # Your command runs inside the Flox environment
    command: ["node", "app.js"]
    resources:
      requests:
        cpu: "100m"
        memory: "128Mi"
```

### Example Workload

An example Flox pod is automatically created in the `flox-workloads` namespace:

```bash
# View the example
kubectl get pod flox-example -n flox-workloads -o yaml

# Check logs
kubectl logs flox-example -n flox-workloads
```

## Configuration Details

### containerd Configuration

The containerd runtime is configured with the Flox shim at `/etc/containerd/config.toml`:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.flox]
  runtime_path = "/usr/local/bin/containerd-shim-flox-v2"
  runtime_type = "io.containerd.runc.v2"
  pod_annotations = ["flox.dev/*"]
  container_annotations = ["flox.dev/*"]
  
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.flox.options]
  SystemdCgroup = true
```

### RuntimeClass

The `flox` RuntimeClass is automatically created with the following configuration:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: flox
handler: flox
scheduling:
  nodeSelector:
    flox.dev/runtime: enabled
```

## Troubleshooting

### Check Flox Shim Installation

```bash
# Verify the shim is installed
ls -la /usr/local/bin/containerd-shim-flox-v2

# Check the installation service
sudo systemctl status install-flox-shim
```

### Verify containerd Configuration

```bash
# Check containerd is running
sudo systemctl status containerd

# View containerd config
sudo cat /etc/containerd/config.toml
```

### Check RuntimeClass

```bash
# List RuntimeClasses
kubectl get runtimeclass

# View Flox RuntimeClass details
kubectl get runtimeclass flox -o yaml
```

### Pod Scheduling Issues

If pods aren't being scheduled:

1. Verify node labels: `kubectl get nodes --show-labels`
2. Check pod events: `kubectl describe pod <pod-name>`
3. Ensure the node has the `flox.dev/runtime=enabled` label

### Flox Environment Issues

If the Flox environment isn't mounting correctly:

1. Check pod annotations: `kubectl get pod <pod-name> -o yaml`
2. Verify the environment exists: `flox list --remote`
3. Check containerd logs: `sudo journalctl -u containerd -f`

## Additional Resources

- [Flox Documentation](https://flox.dev/docs)
- [Flox Imageless Kubernetes Guide](https://flox.dev/kubernetes/)
- [FloxHub](https://hub.flox.dev/)

## Migration Notes

### From CRI-O to containerd

This configuration migrates from CRI-O with btrfs to containerd with ext4/OverlayFS:

- **Container Runtime Endpoint**: Changed from `unix:///run/crio/crio.sock` to `unix:///run/containerd/containerd.sock`
- **Filesystem**: Changed from btrfs to ext4 for better OverlayFS support
- **Storage Driver**: Now uses OverlayFS (containerd default)

**Note**: This is a breaking change that requires a full system reinstall if migrating from an existing CRI-O-based setup.
