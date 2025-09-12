#!/bin/sh

# Kubernetes PKI Certificate Generation Script
# This script generates all certificates required for a Kubernetes cluster
# without relying on easyCerts/CFSSL automation

set -euo pipefail

# Configuration
CERT_DIR="${CERT_DIR:-./k8s-pki}"
MASTER_IP="${MASTER_IP:-10.0.0.10}"
CLUSTER_NAME="${CLUSTER_NAME:-kubernetes}"
SERVICE_CIDR="${SERVICE_CIDR:-10.96.0.0/12}"
CLUSTER_DNS="${CLUSTER_DNS:-10.96.0.10}"

# Certificate validity (10 years)
CERT_DAYS=3650

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    local deps=("openssl" "base64" "agenix")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "$dep is required but not installed"
            exit 1
        fi
    done
    
    # Check if secrets.nix exists
    if [ ! -f "./secrets.nix" ]; then
        log_error "secrets.nix not found. Please run 'agenix init' first."
        exit 1
    fi
}

# Encrypt and save to agenix
encrypt_to_agenix() {
    local data="$1"
    local key_name="$2"
    
    log_info "Encrypting $key_name to agenix..."
    echo "$data" | agenix -e "$key_name"
}

# Create directory structure
setup_directories() {
    log_info "Setting up certificate directories..."
    mkdir -p "$CERT_DIR"/{ca,etcd,apiserver,kubelet,controller-manager,scheduler,proxy,service-account,admin}
    mkdir -p "$CERT_DIR"/kubeconfigs
}

# Generate CA certificate and key
generate_ca() {
    log_info "Generating Cluster CA certificate..."
    
    # CA private key
    openssl genrsa -out /tmp/ca-key.pem 4096
    
    # CA certificate
    openssl req -new -x509 -days "$CERT_DAYS" -key /tmp/ca-key.pem \
        -out /tmp/ca.pem -subj "/CN=kubernetes-ca/O=Kubernetes"
    
    # Encrypt to agenix
    encrypt_to_agenix "$(cat /tmp/ca.pem)" "secrets/k8s-ca.crt.age"
    encrypt_to_agenix "$(cat /tmp/ca-key.pem)" "secrets/k8s-ca.key.age"
    
    # Clean up temp files
    rm -f /tmp/ca.pem /tmp/ca-key.pem
        
    log_info "CA certificate encrypted to agenix"
}

# Generate etcd CA and certificates
generate_etcd_certs() {
    log_info "Generating etcd certificates..."
    
    # etcd CA
    openssl genrsa -out /tmp/etcd-ca-key.pem 4096
    openssl req -new -x509 -days "$CERT_DAYS" -key /tmp/etcd-ca-key.pem \
        -out /tmp/etcd-ca.pem -subj "/CN=etcd-ca/O=Kubernetes"
    
    # Encrypt etcd CA to agenix
    encrypt_to_agenix "$(cat /tmp/etcd-ca.pem)" "secrets/etcd-ca.crt.age"
    encrypt_to_agenix "$(cat /tmp/etcd-ca-key.pem)" "secrets/etcd-ca.key.age"
    
    # etcd server certificate
    openssl genrsa -out /tmp/etcd-server-key.pem 2048
    openssl req -new -key /tmp/etcd-server-key.pem \
        -out /tmp/etcd-server.csr \
        -subj "/CN=etcd-server/O=Kubernetes"
    
    # etcd server certificate with SANs
    cat > /tmp/etcd-server-openssl.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[req_distinguished_name]
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = etcd.local
DNS.3 = etcd.kube-system.svc.cluster.local
IP.1 = 127.0.0.1
IP.2 = $MASTER_IP
EOF

    openssl x509 -req -in /tmp/etcd-server.csr \
        -CA /tmp/etcd-ca.pem -CAkey /tmp/etcd-ca-key.pem \
        -CAcreateserial -out /tmp/etcd-server.pem \
        -days "$CERT_DAYS" -extensions v3_req \
        -extfile /tmp/etcd-server-openssl.conf
    
    # Encrypt etcd server cert to agenix
    encrypt_to_agenix "$(cat /tmp/etcd-server.pem)" "secrets/etcd-server.crt.age"
    encrypt_to_agenix "$(cat /tmp/etcd-server-key.pem)" "secrets/etcd-server.key.age"
    
    # etcd peer certificate (for clustering)
    openssl genrsa -out /tmp/etcd-peer-key.pem 2048
    openssl req -new -key /tmp/etcd-peer-key.pem \
        -out /tmp/etcd-peer.csr \
        -subj "/CN=etcd-peer/O=Kubernetes"
    
    openssl x509 -req -in /tmp/etcd-peer.csr \
        -CA /tmp/etcd-ca.pem -CAkey /tmp/etcd-ca-key.pem \
        -CAcreateserial -out /tmp/etcd-peer.pem \
        -days "$CERT_DAYS" -extensions v3_req \
        -extfile /tmp/etcd-server-openssl.conf
    
    # Encrypt etcd peer cert to agenix
    encrypt_to_agenix "$(cat /tmp/etcd-peer.pem)" "secrets/etcd-peer.crt.age"
    encrypt_to_agenix "$(cat /tmp/etcd-peer-key.pem)" "secrets/etcd-peer.key.age"
    
    # etcd client certificate for apiserver
    openssl genrsa -out /tmp/etcd-apiserver-client-key.pem 2048
    openssl req -new -key /tmp/etcd-apiserver-client-key.pem \
        -out /tmp/etcd-apiserver-client.csr \
        -subj "/CN=etcd-apiserver-client/O=Kubernetes"
    
    openssl x509 -req -in /tmp/etcd-apiserver-client.csr \
        -CA /tmp/etcd-ca.pem -CAkey /tmp/etcd-ca-key.pem \
        -CAcreateserial -out /tmp/etcd-apiserver-client.pem \
        -days "$CERT_DAYS"
    
    # Encrypt etcd apiserver client cert to agenix
    encrypt_to_agenix "$(cat /tmp/etcd-apiserver-client.pem)" "secrets/etcd-apiserver-client.crt.age"
    encrypt_to_agenix "$(cat /tmp/etcd-apiserver-client-key.pem)" "secrets/etcd-apiserver-client.key.age"
    
    # etcd client certificate for flannel
    openssl genrsa -out /tmp/etcd-flannel-client-key.pem 2048
    openssl req -new -key /tmp/etcd-flannel-client-key.pem \
        -out /tmp/etcd-flannel-client.csr \
        -subj "/CN=etcd-flannel-client/O=Kubernetes"
    
    openssl x509 -req -in /tmp/etcd-flannel-client.csr \
        -CA /tmp/etcd-ca.pem -CAkey /tmp/etcd-ca-key.pem \
        -CAcreateserial -out /tmp/etcd-flannel-client.pem \
        -days "$CERT_DAYS"
    
    # Encrypt etcd flannel client cert to agenix
    encrypt_to_agenix "$(cat /tmp/etcd-flannel-client.pem)" "secrets/etcd-flannel-client.crt.age"
    encrypt_to_agenix "$(cat /tmp/etcd-flannel-client-key.pem)" "secrets/etcd-flannel-client.key.age"
    
    # Clean up temp files
    rm -f /tmp/etcd-* 
}

# Generate API server certificate
generate_apiserver_cert() {
    log_info "Generating API server certificate..."
    
    openssl genrsa -out /tmp/apiserver-key.pem 2048
    openssl req -new -key /tmp/apiserver-key.pem \
        -out /tmp/apiserver.csr \
        -subj "/CN=kube-apiserver/O=Kubernetes"
    
    # Use config variables for FQDN
    cat > /tmp/apiserver-openssl.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[req_distinguished_name]
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = kubernetes
DNS.2 = kubernetes.default
DNS.3 = kubernetes.default.svc
DNS.4 = kubernetes.default.svc.cluster.local
DNS.5 = localhost
DNS.6 = ${FQDN:-k3s-dev.batonac.com}
IP.1 = 10.43.0.1
IP.2 = $MASTER_IP
IP.3 = 127.0.0.1
EOF

    # Decrypt CA files temporarily
    agenix -d secrets/k8s-ca.crt.age > /tmp/ca.pem
    agenix -d secrets/k8s-ca.key.age > /tmp/ca-key.pem

    openssl x509 -req -in /tmp/apiserver.csr \
        -CA /tmp/ca.pem -CAkey /tmp/ca-key.pem \
        -CAcreateserial -out /tmp/apiserver.pem \
        -days "$CERT_DAYS" -extensions v3_req \
        -extfile /tmp/apiserver-openssl.conf
    
    # Encrypt apiserver cert to agenix
    encrypt_to_agenix "$(cat /tmp/apiserver.pem)" "secrets/k8s-apiserver.crt.age"
    encrypt_to_agenix "$(cat /tmp/apiserver-key.pem)" "secrets/k8s-apiserver.key.age"
    
    # Clean up temp files
    rm -f /tmp/apiserver* /tmp/ca.pem /tmp/ca-key.pem
}

# Generate admin client certificate
generate_admin_cert() {
    log_info "Generating admin client certificate..."
    
    openssl genrsa -out /tmp/admin-key.pem 2048
    openssl req -new -key /tmp/admin-key.pem \
        -out /tmp/admin.csr \
        -subj "/CN=kubernetes-admin/O=system:masters"
    
    # Decrypt CA files temporarily
    agenix -d secrets/k8s-ca.crt.age > /tmp/ca.pem
    agenix -d secrets/k8s-ca.key.age > /tmp/ca-key.pem

    openssl x509 -req -in /tmp/admin.csr \
        -CA /tmp/ca.pem -CAkey /tmp/ca-key.pem \
        -CAcreateserial -out /tmp/admin.pem \
        -days "$CERT_DAYS"
    
    # Encrypt admin cert to agenix
    encrypt_to_agenix "$(cat /tmp/admin.pem)" "secrets/k8s-admin.crt.age"
    encrypt_to_agenix "$(cat /tmp/admin-key.pem)" "secrets/k8s-admin.key.age"
    
    # Clean up temp files
    rm -f /tmp/admin* /tmp/ca.pem /tmp/ca-key.pem
}

# Generate service account key pair
generate_service_account_keys() {
    log_info "Generating service account keys..."
    
    openssl genrsa -out /tmp/service-account-key.pem 2048
    openssl rsa -in /tmp/service-account-key.pem \
        -pubout -out /tmp/service-account.pem
    
    # Encrypt service account keys to agenix
    encrypt_to_agenix "$(cat /tmp/service-account.pem)" "secrets/k8s-service-account.crt.age"
    encrypt_to_agenix "$(cat /tmp/service-account-key.pem)" "secrets/k8s-service-account.key.age"
    
    # Clean up temp files
    rm -f /tmp/service-account*
}

# Generate kubeconfig file and encrypt to agenix
generate_kubeconfig() {
    local user="$1"
    local cert_name="$2"
    local key_name="$3"
    local output_name="$4"
    
    log_info "Generating kubeconfig for $user..."
    
    # Decrypt CA files temporarily
    agenix -d secrets/k8s-ca.crt.age > /tmp/ca.pem
    agenix -d "$cert_name" > /tmp/cert.pem
    agenix -d "$key_name" > /tmp/key.pem
    
    local ca_data=$(base64 -w 0 /tmp/ca.pem)
    local cert_data=$(base64 -w 0 /tmp/cert.pem)
    local key_data=$(base64 -w 0 /tmp/key.pem)
    
    cat > /tmp/kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: $ca_data
    server: https://${FQDN:-k3s-dev.batonac.com}:6443
  name: $CLUSTER_NAME
contexts:
- context:
    cluster: $CLUSTER_NAME
    user: $user
  name: $user@$CLUSTER_NAME
current-context: $user@$CLUSTER_NAME
users:
- name: $user
  user:
    client-certificate-data: $cert_data
    client-key-data: $key_data
EOF

    # Encrypt kubeconfig to agenix
    encrypt_to_agenix "$(cat /tmp/kubeconfig)" "$output_name"
    
    # Clean up temp files
    rm -f /tmp/ca.pem /tmp/cert.pem /tmp/key.pem /tmp/kubeconfig
}

# Generate kubelet server certificate (for a specific node)
generate_kubelet_server_cert() {
    local node_name="${1:-$(hostname)}"
    local node_ip="${2:-$MASTER_IP}"
    
    log_info "Generating kubelet server certificate for $node_name..."
    
    openssl genrsa -out /tmp/kubelet-server-key.pem 2048
    openssl req -new -key /tmp/kubelet-server-key.pem \
        -out /tmp/kubelet-server.csr \
        -subj "/CN=system:node:$node_name/O=system:nodes"
    
    cat > /tmp/kubelet-server-openssl.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[req_distinguished_name]
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = $node_name
DNS.2 = localhost
IP.1 = $node_ip
IP.2 = 127.0.0.1
EOF

    # Decrypt CA files temporarily
    agenix -d secrets/k8s-ca.crt.age > /tmp/ca.pem
    agenix -d secrets/k8s-ca.key.age > /tmp/ca-key.pem

    openssl x509 -req -in /tmp/kubelet-server.csr \
        -CA /tmp/ca.pem -CAkey /tmp/ca-key.pem \
        -CAcreateserial -out /tmp/kubelet-server.pem \
        -days "$CERT_DAYS" -extensions v3_req \
        -extfile /tmp/kubelet-server-openssl.conf
    
    # Encrypt kubelet certs to agenix
    encrypt_to_agenix "$(cat /tmp/kubelet-server.pem)" "secrets/k8s-kubelet-server.crt.age"
    encrypt_to_agenix "$(cat /tmp/kubelet-server-key.pem)" "secrets/k8s-kubelet-server.key.age"
    
    # Clean up temp files
    rm -f /tmp/kubelet-server* /tmp/ca.pem /tmp/ca-key.pem
}

# Main execution
main() {
    log_info "Starting Kubernetes PKI certificate generation..."
    log_info "Master IP: $MASTER_IP"
    log_info "Service CIDR: $SERVICE_CIDR"
    
    check_dependencies
    
    # Generate CA
    generate_ca
    
    # Generate etcd certificates
    generate_etcd_certs
    
    # Generate API server certificate
    generate_apiserver_cert
    
    # Generate admin client certificate
    generate_admin_cert
    
    # Generate service account keys
    generate_service_account_keys
    
    # Generate kubelet server certificate
    generate_kubelet_server_cert
    
    # Generate admin kubeconfig
    generate_kubeconfig "admin" \
        "secrets/k8s-admin.crt.age" \
        "secrets/k8s-admin.key.age" \
        "secrets/k8s-admin.kubeconfig.age"
    
    log_info "Certificate generation completed successfully!"
    log_info ""
    log_info "All certificates and kubeconfig files are encrypted in agenix."
    log_info "To decrypt the admin kubeconfig:"
    log_info "  agenix -d secrets/k8s-admin.kubeconfig.age > ~/.kube/config"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Environment variables:"
        echo "  CERT_DIR       Certificate output directory (default: ./k8s-pki)"
        echo "  MASTER_IP      Master node IP address (default: 10.0.0.10)"
        echo "  CLUSTER_NAME   Cluster name (default: kubernetes)"
        echo "  SERVICE_CIDR   Service network CIDR (default: 10.96.0.0/12)"
        echo ""
        echo "Example:"
        echo "  MASTER_IP=192.168.1.100 CERT_DIR=/etc/kubernetes/pki $0"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac