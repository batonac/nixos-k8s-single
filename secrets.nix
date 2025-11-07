let
  # Your SSH public key for encryption (so you can edit secrets)
  userKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJTf4eJ30NJHEg7E2m+dpU5mDH7Ou/ooL8dbVd+K6gC/";
  
  # System SSH host key (so the system can decrypt)
  # Get this by running: ssh-keyscan -t ed25519 k3s-dev.batonac.com
  systemKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPz+H/tG0glrE2xIcnGUhbZFvrxz5GzUzQJjONXkITY"; # REPLACE WITH ACTUAL SYSTEM SSH KEY
in
{
  # Cloudflare secrets only
  "secrets/cloudflare-email.age".publicKeys = [ userKey systemKey ];
  "secrets/cloudflare-dns-api-token.age".publicKeys = [ userKey systemKey ];

  # Kubernetes internal PKI
  "secrets/k8s-ca.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-ca.key.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-apiserver.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-apiserver.key.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-admin.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-admin.key.age".publicKeys = [ userKey systemKey ];

  # etcd dedicated PKI
  "secrets/etcd-ca.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/etcd-ca.key.age".publicKeys = [ userKey systemKey ];
  "secrets/etcd-server.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/etcd-server.key.age".publicKeys = [ userKey systemKey ];
  "secrets/etcd-peer.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/etcd-peer.key.age".publicKeys = [ userKey systemKey ];
  "secrets/etcd-apiserver-client.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/etcd-apiserver-client.key.age".publicKeys = [ userKey systemKey ];
  "secrets/etcd-flannel-client.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/etcd-flannel-client.key.age".publicKeys = [ userKey systemKey ];

  # Service account keys
  "secrets/k8s-service-account.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-service-account.key.age".publicKeys = [ userKey systemKey ];

  # Kubernetes component client certificates
  "secrets/k8s-controller-manager.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-controller-manager.key.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-scheduler.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-scheduler.key.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-proxy.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-proxy.key.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-kubelet.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-kubelet.key.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-kubelet-server.crt.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-kubelet-server.key.age".publicKeys = [ userKey systemKey ];

  # Kubeconfig files
  "secrets/k8s-admin.kubeconfig.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-controller-manager.kubeconfig.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-scheduler.kubeconfig.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-proxy.kubeconfig.age".publicKeys = [ userKey systemKey ];
  "secrets/k8s-kubelet.kubeconfig.age".publicKeys = [ userKey systemKey ];
  
  # No addon-manager secrets needed!
}