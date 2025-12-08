#!/usr/bin/env bash
# Label Kubernetes nodes for Flox Imageless Kubernetes runtime

set -euo pipefail

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl not found. Please install kubectl first."
    exit 1
fi

# Get node name from argument or use current hostname
NODE_NAME="${1:-$(hostname)}"

echo "Labeling node '${NODE_NAME}' for Flox runtime..."

# Add the Flox runtime label
kubectl label node "${NODE_NAME}" flox.dev/runtime=enabled --overwrite

# Verify the label was added
if kubectl get node "${NODE_NAME}" -o jsonpath='{.metadata.labels.flox\.dev/runtime}' 2>/dev/null | grep -q "enabled"; then
    echo "✓ Successfully labeled node '${NODE_NAME}'"
    echo ""
    echo "Node labels:"
    kubectl get node "${NODE_NAME}" --show-labels | grep -o 'flox.dev/runtime=enabled' || true
else
    echo "✗ Failed to label node '${NODE_NAME}'"
    exit 1
fi

echo ""
echo "Flox runtime is now enabled on node '${NODE_NAME}'"
echo "You can now schedule Flox workloads using runtimeClassName: flox"
