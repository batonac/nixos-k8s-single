#!/usr/bin/env bash
set -euo pipefail

# generate-internal-pki.sh
# Generates internal Kubernetes & etcd PKI, encrypts artifacts with agenix (secrets.nix recipients),
# and writes *.age files into ./secrets matching secrets.nix entries.
# Usage: ./scripts/generate-internal-pki.sh --fqdn k3s-dev.batonac.com --ip 10.48.4.181 --service-cidr 10.43.0.0/16 [--force]

FQDN=""
IP_ADDR=""
SERVICE_CIDR=""
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fqdn) FQDN="$2"; shift 2;;
    --ip) IP_ADDR="$2"; shift 2;;
    --service-cidr) SERVICE_CIDR="$2"; shift 2;;
    --force) FORCE=1; shift;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# //' ; exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

[[ -n $FQDN && -n $IP_ADDR && -n $SERVICE_CIDR ]] || { echo "Missing required args" >&2; exit 1; }

command -v openssl >/dev/null || { echo "openssl required" >&2; exit 1; }
command -v agenix  >/dev/null || { echo "agenix required"  >&2; exit 1; }

# Derive service IP (first usable host in CIDR)
SERVICE_NET="${SERVICE_CIDR%/*}"
if [[ $SERVICE_NET =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.0$ ]]; then
  SERVICE_IP="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}.1"
else
  SERVICE_IP=$(python3 -c 'import ipaddress,sys; net=ipaddress.ip_network(sys.argv[1],strict=False); print(next(net.hosts()))' "$SERVICE_CIDR") || {
    echo "Failed to derive service IP" >&2; exit 1; }
fi

ROOT_DIR=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
SECRETS_DIR="$ROOT_DIR/secrets"
WORK_DIR=$(mktemp -d)
K8S_DIR="$WORK_DIR/k8s"; ETCD_DIR="$WORK_DIR/etcd"
mkdir -p "$SECRETS_DIR" "$K8S_DIR" "$ETCD_DIR"
trap 'rm -rf "$WORK_DIR"' EXIT

SECRETS_NIX="$ROOT_DIR/secrets.nix"
[[ -f $SECRETS_NIX ]] || { echo "secrets.nix not found (expected at $SECRETS_NIX)" >&2; exit 1; }

# Decrypt existing CA (reuse identity) via agenix
maybe_decrypt() {
  local base=$1 type=$2 targetDir=$3
  local keyAge="secrets/${base}.key.age" crtAge="secrets/${base}.crt.age"
  if [[ -f "$ROOT_DIR/$keyAge" ]]; then
    echo "Reusing existing $base (agenix decrypt)"
    ( cd "$ROOT_DIR"; agenix -d "$keyAge" ) > "$targetDir/${type}-ca.key"
    if [[ -f "$ROOT_DIR/$crtAge" ]]; then
      ( cd "$ROOT_DIR"; agenix -d "$crtAge" ) > "$targetDir/${type}-ca.crt" || true
    fi
  fi
}
maybe_decrypt k8s-ca k8s "$K8S_DIR"
maybe_decrypt etcd-ca etcd "$ETCD_DIR"

# Encrypt helper using agenix (stdin)
enc() {
  local src=$1 dst=$2
  local rel=${dst#$ROOT_DIR/}
  if [[ -f $dst && $FORCE -ne 1 ]]; then echo "Skip (exists): ${rel}"; return; fi
  ( cd "$ROOT_DIR"; agenix -e "$rel" < "$src" )
  echo "Wrote $rel"
}

mk_openssl_cfg() {
  local cn=$1 sans=$2 usages=$3 outfile=$4 org=$5
  cat > "$outfile" <<EOF
[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt = no

[ req_distinguished_name ]
CN = $cn
O = ${org:-}

[ v3_req ]
subjectAltName = $sans
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = $usages
basicConstraints = CA:FALSE
EOF
}

mk_ca() {
  local cn=$1 dir=$2 prefix=$3 days=${4:-3650}
  [[ -f $dir/${prefix}-ca.key ]] || openssl genrsa -out $dir/${prefix}-ca.key 4096
  [[ -f $dir/${prefix}-ca.crt ]] || openssl req -x509 -new -nodes -key $dir/${prefix}-ca.key -subj "/CN=$cn" -days $days -out $dir/${prefix}-ca.crt
}

issue_cert() {
  local caKey=$1 caCrt=$2 cn=$3 sans=$4 usages=$5 outPrefix=$6 org=$7
  local key=${outPrefix}.key crt=${outPrefix}.crt
  if [[ -f $key && -f $crt && $FORCE -ne 1 ]]; then return; fi
  local cfg=$(mktemp)
  mk_openssl_cfg "$cn" "$sans" "$usages" "$cfg" "$org"
  openssl genrsa -out "$key" 4096
  openssl req -new -key "$key" -out "${outPrefix}.csr" -config "$cfg"
  openssl x509 -req -in "${outPrefix}.csr" -CA "$caCrt" -CAkey "$caKey" -CAcreateserial -out "$crt" -days 825 -extensions v3_req -extfile "$cfg"
  rm -f "${outPrefix}.csr" "$cfg"
}

# Kubernetes CA / certs
mk_ca kubernetes-ca "$K8S_DIR" k8s
APISERVER_SANS="DNS:$FQDN,DNS:kubernetes,DNS:kubernetes.default,DNS:kubernetes.default.svc,DNS:kubernetes.default.svc.cluster,DNS:kubernetes.default.svc.cluster.local,IP:$IP_ADDR,IP:$SERVICE_IP,IP:127.0.0.1"
issue_cert "$K8S_DIR/k8s-ca.key" "$K8S_DIR/k8s-ca.crt" kubernetes "$APISERVER_SANS" "serverAuth,clientAuth" "$K8S_DIR/apiserver" "system:apiserver"
issue_cert "$K8S_DIR/k8s-ca.key" "$K8S_DIR/k8s-ca.crt" admin "DNS:admin" "clientAuth" "$K8S_DIR/admin" "system:masters"

# etcd CA / certs
mk_ca etcd-ca "$ETCD_DIR" etcd
ETCD_SANS="DNS:$FQDN,IP:$IP_ADDR,IP:127.0.0.1"
issue_cert "$ETCD_DIR/etcd-ca.key" "$ETCD_DIR/etcd-ca.crt" etcd-server "$ETCD_SANS" "serverAuth,clientAuth" "$ETCD_DIR/server" "system:etcd"
issue_cert "$ETCD_DIR/etcd-ca.key" "$ETCD_DIR/etcd-ca.crt" etcd-peer   "$ETCD_SANS" "serverAuth,clientAuth" "$ETCD_DIR/peer"   "system:etcd-peers"
issue_cert "$ETCD_DIR/etcd-ca.key" "$ETCD_DIR/etcd-ca.crt" kube-apiserver "DNS:kube-apiserver" "clientAuth" "$ETCD_DIR/apiserver-client" "system:masters"
issue_cert "$ETCD_DIR/etcd-ca.key" "$ETCD_DIR/etcd-ca.crt" flannel "DNS:flannel" "clientAuth" "$ETCD_DIR/flannel-client" "system:flannel"

# Encrypt to secrets/*.age (paths must match secrets.nix entries)
copy_and_encrypt() {
  local crt=$1 key=$2 base=$3
  enc "$crt" "$SECRETS_DIR/${base}.crt.age"
  enc "$key" "$SECRETS_DIR/${base}.key.age"
}
copy_and_encrypt "$K8S_DIR/k8s-ca.crt" "$K8S_DIR/k8s-ca.key" k8s-ca
copy_and_encrypt "$K8S_DIR/apiserver.crt" "$K8S_DIR/apiserver.key" k8s-apiserver
copy_and_encrypt "$K8S_DIR/admin.crt" "$K8S_DIR/admin.key" k8s-admin
copy_and_encrypt "$ETCD_DIR/etcd-ca.crt" "$ETCD_DIR/etcd-ca.key" etcd-ca
copy_and_encrypt "$ETCD_DIR/server.crt" "$ETCD_DIR/server.key" etcd-server
copy_and_encrypt "$ETCD_DIR/peer.crt" "$ETCD_DIR/peer.key" etcd-peer
copy_and_encrypt "$ETCD_DIR/apiserver-client.crt" "$ETCD_DIR/apiserver-client.key" etcd-apiserver-client
copy_and_encrypt "$ETCD_DIR/flannel-client.crt" "$ETCD_DIR/flannel-client.key" etcd-flannel-client

echo "Done. Encrypted secrets updated in ./secrets/*.age"