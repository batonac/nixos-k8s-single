let
  # Your SSH public key for encryption (so you can edit secrets)
  userKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJTf4eJ30NJHEg7E2m+dpU5mDH7Ou/ooL8dbVd+K6gC/";
  
  # Shared age public key (private key deployed via AGENIX_KEY env var)
  # Generate with: age-keygen
  # Store the SECRET key in AGENIX_KEY env var, put the PUBLIC key here
  ageKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH5kb3m13bpdXV+WxhNpstdWxv8j2UsAUQxsxD37USmM"; # REPLACE with age public key
in
{
  # Cloudflare secrets only
  "secrets/cloudflare-email.age".publicKeys = [ userKey ageKey ];
  "secrets/cloudflare-dns-api-token.age".publicKeys = [ userKey ageKey ];

  # Kubernetes internal PKI
  "secrets/k8s-ca.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-ca.key.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-apiserver.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-apiserver.key.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-admin.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-admin.key.age".publicKeys = [ userKey ageKey ];

  # etcd dedicated PKI
  "secrets/etcd-ca.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/etcd-ca.key.age".publicKeys = [ userKey ageKey ];
  "secrets/etcd-server.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/etcd-server.key.age".publicKeys = [ userKey ageKey ];
  "secrets/etcd-peer.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/etcd-peer.key.age".publicKeys = [ userKey ageKey ];
  "secrets/etcd-apiserver-client.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/etcd-apiserver-client.key.age".publicKeys = [ userKey ageKey ];
  "secrets/etcd-flannel-client.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/etcd-flannel-client.key.age".publicKeys = [ userKey ageKey ];

  # Service account keys
  "secrets/k8s-service-account.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-service-account.key.age".publicKeys = [ userKey ageKey ];

  # Kubernetes component client certificates
  "secrets/k8s-controller-manager.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-controller-manager.key.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-scheduler.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-scheduler.key.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-proxy.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-proxy.key.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-kubelet.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-kubelet.key.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-kubelet-server.crt.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-kubelet-server.key.age".publicKeys = [ userKey ageKey ];

  # Kubeconfig files
  "secrets/k8s-admin.kubeconfig.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-controller-manager.kubeconfig.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-scheduler.kubeconfig.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-proxy.kubeconfig.age".publicKeys = [ userKey ageKey ];
  "secrets/k8s-kubelet.kubeconfig.age".publicKeys = [ userKey ageKey ];
  
  # No addon-manager secrets needed!
}