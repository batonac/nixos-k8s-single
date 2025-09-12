#!/usr/bin/env python3
"""
generate-internal-pki.py
Generates internal Kubernetes & etcd PKI, encrypts artifacts with agenix (using secrets.nix),
and writes *.age files into ./secrets matching secrets.nix entries.

Features:
- Reuses existing CA keys by decrypting existing *.age files (k8s-ca, etcd-ca) via agenix.
- Generates only missing leaf certs unless --force is given.
- Uses openssl via subprocess (no extra Python crypto deps).
- Service cluster IP auto-derived from --service-cidr (first usable host).
- No manual parsing of recipient keys; relies on agenix secrets.nix mapping.

Usage:
  ./scripts/generate-internal-pki.py --fqdn k3s-dev.batonac.com --ip 10.48.4.181 --service-cidr 10.43.0.0/16 [--force]

Requires: openssl, agenix, python3
"""
import argparse
import ipaddress
import shlex
import subprocess as sp
import sys
import tempfile
from pathlib import Path

OPENSSL_DAYS_CA = 3650
OPENSSL_DAYS_LEAF = 825

class CmdError(RuntimeError):
    pass

def run(cmd: str, **kw):
    proc = sp.run(cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE, text=True, **kw)
    if proc.returncode != 0:
        raise CmdError(f"Command failed: {cmd}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    return proc.stdout

def which(binary: str):
    return sp.call(["which", binary], stdout=sp.DEVNULL, stderr=sp.DEVNULL) == 0

REQUIRED_BINS = ["openssl", "agenix"]

def parse_args():
    ap = argparse.ArgumentParser(description="Generate internal Kubernetes & etcd PKI (encrypted with agenix)")
    ap.add_argument("--fqdn", required=True)
    ap.add_argument("--ip", required=True)
    ap.add_argument("--service-cidr", required=True)
    ap.add_argument("--force", action="store_true", help="Regenerate leaf certs even if they exist")
    return ap.parse_args()

# ----- CA / cert helpers -----

def ensure_ca(dir_: Path, cn: str, prefix: str):
    key = dir_ / f"{prefix}-ca.key"
    crt = dir_ / f"{prefix}-ca.crt"
    if key.exists() and crt.exists():
        return key, crt
    if not key.exists():
        run(f"openssl genrsa -out {shlex.quote(str(key))} 4096")
    if not crt.exists():
        run(f"openssl req -x509 -new -nodes -key {shlex.quote(str(key))} -subj /CN={cn} -days {OPENSSL_DAYS_CA} -out {shlex.quote(str(crt))}")
    return key, crt

def issue_cert(ca_key: Path, ca_crt: Path, cn: str, sans: list[str], usages: list[str], out_prefix: Path, org: str, force: bool):
    key = out_prefix.with_suffix('.key')
    crt = out_prefix.with_suffix('.crt')
    if key.exists() and crt.exists() and not force:
        return key, crt
    cfg = out_prefix.parent / (out_prefix.name + '.openssl.cnf')
    san_str = ','.join(sans)
    eku = ','.join(usages)
    cfg.write_text(f"""[ req ]\n"""
                   f"default_bits = 4096\n"
                   f"distinguished_name = req_distinguished_name\n"
                   f"req_extensions = v3_req\n"
                   f"prompt = no\n\n"
                   f"[ req_distinguished_name ]\nCN = {cn}\nO = {org}\n\n"
                   f"[ v3_req ]\nsubjectAltName = {san_str}\n"
                   f"keyUsage = critical, digitalSignature, keyEncipherment\n"
                   f"extendedKeyUsage = {eku}\n"
                   f"basicConstraints = CA:FALSE\n")
    run(f"openssl genrsa -out {shlex.quote(str(key))} 4096")
    csr = out_prefix.with_suffix('.csr')
    run(f"openssl req -new -key {shlex.quote(str(key))} -out {shlex.quote(str(csr))} -config {shlex.quote(str(cfg))}")
    run(f"openssl x509 -req -in {shlex.quote(str(csr))} -CA {shlex.quote(str(ca_crt))} -CAkey {shlex.quote(str(ca_key))} -CAcreateserial -out {shlex.quote(str(crt))} -days {OPENSSL_DAYS_LEAF} -extensions v3_req -extfile {shlex.quote(str(cfg))}")
    csr.unlink(missing_ok=True)
    cfg.unlink(missing_ok=True)
    return key, crt

# ----- agenix helpers -----

def agenix_decrypt(secret_path: Path) -> str:
    return run(f"agenix -d {shlex.quote(str(secret_path))}")

def agenix_encrypt(src: Path, dst: Path, force: bool):
    if dst.exists() and not force:
        print(f"Skip (exists): {dst.name}")
        return
    # agenix -e reads from stdin, writes to dst
    data = src.read_bytes()
    proc = sp.run(["agenix", "-e", str(dst)], input=data, stdout=sp.PIPE, stderr=sp.PIPE)
    if proc.returncode != 0:
        raise CmdError(f"agenix encryption failed for {dst}: {proc.stderr.decode()}")
    print(f"Wrote {dst}")

def reuse_ca_if_present(base: str, type_prefix: str, work_dir: Path, secrets_dir: Path):
    key_age = secrets_dir / f"{base}.key.age"
    crt_age = secrets_dir / f"{base}.crt.age"
    if key_age.exists():
        print(f"Reusing existing {base} (decrypting via agenix)")
        key_out = work_dir / f"{type_prefix}-ca.key"
        crt_out = work_dir / f"{type_prefix}-ca.crt"
        key_out.write_text(agenix_decrypt(key_age))
        if crt_age.exists():
            crt_out.write_text(agenix_decrypt(crt_age))

# ----- main -----

def main():
    args = parse_args()
    for b in REQUIRED_BINS:
        if not which(b):
            print(f"Missing required binary: {b}", file=sys.stderr)
            return 1

    try:
        service_net = ipaddress.ip_network(args.service_cidr, strict=False)
        service_ip = str(next(service_net.hosts()))
    except Exception as e:
        print(f"Failed to derive service IP: {e}", file=sys.stderr)
        return 1

    root_dir = Path(run("git rev-parse --show-toplevel 2>/dev/null || pwd").strip())
    secrets_dir = root_dir / "secrets"
    secrets_dir.mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        k8s_dir = work / "k8s"; k8s_dir.mkdir()
        etcd_dir = work / "etcd"; etcd_dir.mkdir()

        # Reuse CA keys if present
        reuse_ca_if_present("k8s-ca", "k8s", k8s_dir, secrets_dir)
        reuse_ca_if_present("etcd-ca", "etcd", etcd_dir, secrets_dir)

        # Ensure CAs
        k8s_ca_key, k8s_ca_crt = ensure_ca(k8s_dir, "kubernetes-ca", "k8s")
        etcd_ca_key, etcd_ca_crt = ensure_ca(etcd_dir, "etcd-ca", "etcd")

        # Kubernetes certs
        apiserver_sans = [
            f"DNS:{args.fqdn}",
            "DNS:kubernetes",
            "DNS:kubernetes.default",
            "DNS:kubernetes.default.svc",
            "DNS:kubernetes.default.svc.cluster",
            "DNS:kubernetes.default.svc.cluster.local",
            f"IP:{args.ip}",
            f"IP:{service_ip}",
            "IP:127.0.0.1",
        ]
        issue_cert(k8s_ca_key, k8s_ca_crt, "kubernetes", apiserver_sans, ["serverAuth","clientAuth"], k8s_dir/"apiserver", "system:apiserver", args.force)
        issue_cert(k8s_ca_key, k8s_ca_crt, "admin", ["DNS:admin"], ["clientAuth"], k8s_dir/"admin", "system:masters", args.force)

        # etcd certs
        etcd_sans = [f"DNS:{args.fqdn}", f"IP:{args.ip}", "IP:127.0.0.1"]
        issue_cert(etcd_ca_key, etcd_ca_crt, "etcd-server", etcd_sans, ["serverAuth","clientAuth"], etcd_dir/"server", "system:etcd", args.force)
        issue_cert(etcd_ca_key, etcd_ca_crt, "etcd-peer", etcd_sans, ["serverAuth","clientAuth"], etcd_dir/"peer", "system:etcd-peers", args.force)
        issue_cert(etcd_ca_key, etcd_ca_crt, "kube-apiserver", ["DNS:kube-apiserver"], ["clientAuth"], etcd_dir/"apiserver-client", "system:masters", args.force)
        issue_cert(etcd_ca_key, etcd_ca_crt, "flannel", ["DNS:flannel"], ["clientAuth"], etcd_dir/"flannel-client", "system:flannel", args.force)

        # Encrypt artifacts via agenix
        mapping = [
            (k8s_ca_crt, k8s_ca_key, "k8s-ca"),
            (k8s_dir/"apiserver.crt", k8s_dir/"apiserver.key", "k8s-apiserver"),
            (k8s_dir/"admin.crt", k8s_dir/"admin.key", "k8s-admin"),
            (etcd_ca_crt, etcd_ca_key, "etcd-ca"),
            (etcd_dir/"server.crt", etcd_dir/"server.key", "etcd-server"),
            (etcd_dir/"peer.crt", etcd_dir/"peer.key", "etcd-peer"),
            (etcd_dir/"apiserver-client.crt", etcd_dir/"apiserver-client.key", "etcd-apiserver-client"),
            (etcd_dir/"flannel-client.crt", etcd_dir/"flannel-client.key", "etcd-flannel-client"),
        ]
        for crt, key, base in mapping:
            agenix_encrypt(crt, secrets_dir / f"{base}.crt.age", args.force)
            agenix_encrypt(key, secrets_dir / f"{base}.key.age", args.force)

    print("Done. Encrypted secrets updated in ./secrets/*.age")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except CmdError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Aborted", file=sys.stderr)
        sys.exit(130)
