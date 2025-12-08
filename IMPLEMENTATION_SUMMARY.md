# Implementation Summary: Flox Imageless Kubernetes

## Overview

This implementation adds comprehensive support for Flox Imageless Kubernetes to the nixos-k8s-single repository, enabling deployment of workloads using Flox environments instead of traditional container images.

## What is Flox Imageless Kubernetes?

Flox Imageless Kubernetes is a novel approach to Kubernetes deployments that eliminates the need for container image builds. Instead of packaging applications into Docker/OCI images, developers define their application environment using Flox, and the runtime directly mounts that environment into pods.

### Key Benefits

1. **No Image Builds**: Eliminates the Docker build process entirely
2. **Faster Deployments**: No need to push/pull large container images
3. **Reproducible Environments**: Flox lockfiles ensure consistency across all stages
4. **Simplified Workflow**: Define once, use everywhere (dev, test, production)

## Changes Implemented

### 1. Container Runtime Migration (Breaking Change)

**From**: CRI-O with btrfs storage
**To**: containerd with crun as default OCI runtime, OverlayFS on ext4

**Rationale**: 
- Flox requires containerd-shim-flox-v2, which integrates with containerd
- OverlayFS is the recommended storage driver for containerd
- ext4 provides better performance for OverlayFS than btrfs
- crun is retained as the default OCI runtime for better performance

**Impact**: Requires full system reinstall for existing deployments

### 2. Filesystem Changes

**Modified**: `flake.nix` disko configuration (lines 311-326)

Changed root filesystem from btrfs to ext4:
```nix
format = "ext4";
mountOptions = [ "noatime" ];
```

Updated boot.initrd.supportedFilesystems:
```nix
supportedFilesystems = {
  ext4 = true;
  vfat = true;
  zfs = lib.mkForce false;
};
```

### 3. Container Runtime Configuration

**Modified**: `flake.nix` virtualisation section (lines 1056-1093)

- Removed entire CRI-O configuration block
- Added containerd configuration with:
  - Version 2 config format
  - CNI integration with flannel
  - Default crun OCI runtime (retaining from CRI-O setup)
  - Fallback runc runtime available
  - Flox runtime with proper annotations

Default runtime configuration:
```nix
crun = {
  runtime_type = "io.containerd.runc.v2";
  options = {
    BinaryName = "${pkgs.crun}/bin/crun";
    SystemdCgroup = true;
  };
};
```

Flox runtime configuration:
```nix
flox = {
  runtime_path = "/usr/local/bin/containerd-shim-flox-v2";
  runtime_type = "io.containerd.runc.v2";
  pod_annotations = [ "flox.dev/*" ];
  container_annotations = [ "flox.dev/*" ];
  options = {
    SystemdCgroup = true;
  };
};
```

### 4. Kubelet Configuration

**Modified**: `flake.nix` kubelet section (lines 833-841)

- Changed containerRuntimeEndpoint: `unix:///run/containerd/containerd.sock`
- Updated runtime-cgroups: `/system.slice/containerd.service`
- Added service dependencies:
  - containerd.service
  - install-flox-shim.service

### 5. Flox Shim Installation

**Added**: Systemd service `install-flox-shim` (lines 1020-1070)

Features:
- Attempts automatic installation using Flox installer
- Falls back to manual installation if automatic fails
- Supports both containerd 2.x and 1.7.x shim versions
- Uses system architecture variable for portability
- Creates symlink at `/usr/local/bin/containerd-shim-flox-v2`
- Runs before containerd.service starts

Installation process:
1. Try: `flox activate -r flox/containerd-shim-flox-installer --trust`
2. Fallback: Manual Flox environment creation and package installation
3. Verify: Check shim executable exists and is functional

### 6. Kubernetes RuntimeClass

**Created**: `addons/flox-runtime.nix`

Defines Flox RuntimeClass:
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

### 7. Example Workload

**Created**: Example namespace and pod in `addons/flox-runtime.nix`

- Namespace: `flox-workloads`
- Example pod: `flox-example`
- Uses placeholder environment (requires user configuration)
- Demonstrates Flox annotation usage

### 8. Documentation

**Created**: `FLOX_IMAGELESS_K8S.md`

Comprehensive documentation covering:
- Breaking change warnings
- Installation verification steps
- Node labeling requirements
- Usage examples
- Troubleshooting guide
- Configuration details

### 9. Helper Script

**Created**: `scripts/label-node-for-flox.sh`

Utility script to label nodes with `flox.dev/runtime=enabled`:
- Accepts node name as argument or uses hostname
- Validates label application
- Includes error handling

### 10. Addon System Integration

**Modified**: `addons/default.nix`

Added flox-runtime to enabled addons list:
```nix
enabledAddons = [
  "rbac-bootstrap"
  "dns"
  "namespaces"
  "test-workloads"
  "flox-runtime"
];
```

## File Changes Summary

| File | Status | Changes |
|------|--------|---------|
| `flake.nix` | Modified | CRI-O → containerd, btrfs → ext4, kubelet config, systemd service |
| `addons/default.nix` | Modified | Added flox-runtime to enabled addons |
| `addons/flox-runtime.nix` | Created | RuntimeClass, example workload, namespace |
| `FLOX_IMAGELESS_K8S.md` | Created | Comprehensive documentation |
| `scripts/label-node-for-flox.sh` | Created | Node labeling helper script |

## Usage

### Initial Setup

1. **Deploy the updated configuration** (requires fresh install if migrating)

2. **Label nodes for Flox**:
   ```bash
   kubectl label node <node-name> flox.dev/runtime=enabled
   # Or use the helper script
   ./scripts/label-node-for-flox.sh
   ```

3. **Verify installation**:
   ```bash
   # Check containerd
   sudo systemctl status containerd
   
   # Check Flox shim
   ls -la /usr/local/bin/containerd-shim-flox-v2
   
   # Check RuntimeClass
   kubectl get runtimeclass flox
   ```

### Deploying Flox Workloads

1. **Create Flox environment**:
   ```bash
   mkdir my-app
   cd my-app
   flox init
   flox install nodejs npm
   ```

2. **Publish to FloxHub**:
   ```bash
   flox publish floxhub/<org>/<environment>
   ```

3. **Deploy to Kubernetes**:
   ```yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: my-app
     annotations:
       flox.dev/environment: "floxhub/<org>/<environment>"
   spec:
     runtimeClassName: flox
     containers:
     - name: app
       image: registry.k8s.io/pause:3.9
       command: ["node", "app.js"]
   ```

## Testing Checklist

- [ ] Fresh NixOS installation with updated flake
- [ ] containerd service running and healthy
- [ ] Flox shim installed at `/usr/local/bin/containerd-shim-flox-v2`
- [ ] RuntimeClass `flox` created successfully
- [ ] Node labeled with `flox.dev/runtime=enabled`
- [ ] Example namespace `flox-workloads` created
- [ ] Deploy test Flox workload
- [ ] Verify pod starts using Flox runtime
- [ ] Check containerd logs for any issues

## Known Limitations

1. **Example pod requires configuration**: The example pod uses a placeholder environment and must be updated with a real Flox environment to run
2. **Architecture-specific**: Currently configured for x86_64-linux (though portable with system variable)
3. **Manual node labeling**: Nodes must be manually labeled for Flox scheduling

## Security Considerations

- Flox shim runs with elevated privileges (required for container runtime)
- Flox environments are pulled from FloxHub (or configured registry)
- Pod security policies should be configured appropriately
- Network policies may be needed to restrict Flox environment access

## Future Enhancements

Potential improvements for future iterations:

1. **Automatic node labeling**: Label nodes automatically during bootstrap
2. **Multi-architecture support**: Test and document ARM64 support
3. **Private FloxHub**: Instructions for self-hosted FloxHub
4. **Monitoring integration**: Metrics for Flox environment usage
5. **Resource quotas**: Limits on Flox environment size/resources
6. **Cache optimization**: Local caching of Flox environments

## Migration Guide

### From Existing CRI-O Setup

**⚠️ WARNING: This is a destructive operation**

1. **Backup critical data**:
   - Export all Kubernetes manifests
   - Backup etcd data
   - Save persistent volume data
   - Document all configurations

2. **Reinstall system**:
   - Use updated flake.nix
   - Provision fresh with ext4 filesystem
   - containerd will be configured automatically

3. **Restore data**:
   - Re-apply Kubernetes manifests
   - Restore persistent volumes
   - Verify all services running

### For Fresh Installations

No special considerations - simply deploy with the updated configuration.

## Support and Troubleshooting

See `FLOX_IMAGELESS_K8S.md` for detailed troubleshooting steps.

Common issues:
- **Shim not found**: Restart `install-flox-shim.service`
- **Pods not scheduling**: Check node labels
- **Environment not found**: Verify FloxHub connectivity and environment reference

## References

- [Flox Documentation](https://flox.dev/docs)
- [Flox Imageless Kubernetes](https://flox.dev/kubernetes/)
- [FloxHub](https://hub.flox.dev/)
- [containerd Documentation](https://containerd.io/docs/)

---

**Implementation Date**: December 2024
**NixOS Version**: 25.11
**containerd Version**: 2.x (with fallback to 1.7 support)
**Kubernetes Version**: 1.28
