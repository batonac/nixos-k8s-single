{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    vscode-server = {
      url = "github:nix-community/nixos-vscode-server";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    kubenix = {
      url = "github:hall/kubenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    agenix = {
      url = "github:ryantm/agenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    juicefs-csi-driver = {
      url = "github:juicedata/juicefs-csi-driver";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      disko,
      vscode-server,
      kubenix,
      agenix,
      ...
    }:
    let
      # Configuration variables
      hostName = "k3s-dev"; # Replace with desired hostname
      domain = "batonac.com"; # Replace with your domain
      fqdn = "${hostName}.${domain}"; # Fully qualified domain name
      diskDevice = "/dev/sda"; # Replace with your disk device
      timeZone = "America/New_York"; # Replace with your timezone
      locale = "en_US.UTF-8"; # Replace with your locale
      username = "nixos"; # Replace with desired username
      initialPassword = "password"; # Replace with a secure password
      ipAddress = "10.48.4.181";
      stateVersion = "25.11"; # NixOS state version
      sshKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv4SpIhHJqtRaYBRQOin4PTDUxRwo7ozoQHTUFjMGLW avunu@AvunuCentral"; # Replace with your SSH public key
      extraPackages = with nixpkgs.legacyPackages.x86_64-linux; [
        coreutils
        curl
        kubectl
        kubernetes-helm
        nettools
        nixfmt-rfc-style
        openssl
        service-wrapper
        wget
      ];
    in
    {
      # Kubenix package for generating Kubernetes manifests
      packages.x86_64-linux.kubenix-manifests =
        (kubenix.evalModules.x86_64-linux {
          module =
            { kubenix, ... }:
            {
              imports = [ kubenix.modules.k8s ];
              kubenix.project = "k3s-dev";
              kubernetes.version = "1.28";

              kubernetes.resources = {
                # Test namespace
                namespaces.test = { };

                # Cert-manager namespace
                namespaces.cert-manager = { };

                # JuiceFS CSI namespace
                namespaces.juicefs-csi = { };

                # Simple test pod
                pods.alpine-test = {
                  metadata.namespace = "default";
                  spec = {
                    containers.alpine = {
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
                    };
                    restartPolicy = "Always";
                  };
                };

                # Example deployment for testing
                deployments.nginx = {
                  metadata.namespace = "default";
                  spec = {
                    replicas = 2;
                    selector.matchLabels.app = "nginx";
                    template = {
                      metadata.labels.app = "nginx";
                      spec = {
                        containers.nginx = {
                          image = "nginx:1.25";
                          imagePullPolicy = "IfNotPresent";
                          ports = [
                            {
                              containerPort = 80;
                            }
                          ];
                        };
                      };
                    };
                  };
                };

                # Service for nginx
                services.nginx = {
                  metadata.namespace = "default";
                  spec = {
                    selector.app = "nginx";
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
            };
        }).config.kubernetes.result;

      # Development shell with secret management tools
      devShells.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.mkShell {
        buildInputs = with nixpkgs.legacyPackages.x86_64-linux; [
          agenix.packages.x86_64-linux.default
          ssh-to-age
          age
          openssh
          openssl
          nixfmt-rfc-style
        ];

        shellHook = ''
          echo "🔐 NixOS K8s Secrets Management Shell"
          echo ""
          echo "Available tools:"
          echo "  agenix       - Encrypt/decrypt secrets"
          echo "  ssh-to-age   - Convert SSH keys to age format"
          echo "  age          - Age encryption tool"
          echo ""
          echo "Scripts:"
          echo "  ./setup-secrets.sh - Create encrypted secrets"
          echo "  ./get-age-key.sh   - Get system age key"
          echo ""
          echo "Usage:"
          echo "  1. Run: ./setup-secrets.sh"
          echo "  2. Then: ./update.sh"
          echo ""
        '';
      };

      nixosConfigurations = {
        "${hostName}" = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            { nix.nixPath = [ "nixpkgs=${self.inputs.nixpkgs}" ]; }
            vscode-server.nixosModules.default
            disko.nixosModules.disko
            agenix.nixosModules.default
            (
              {
                config,
                lib,
                pkgs,
                modulesPath,
                ...
              }:
              {
                imports = [
                  (modulesPath + "/profiles/qemu-guest.nix")
                  ./addons
                ];

                boot = {
                  initrd = {
                    availableKernelModules = [
                      "ahci"
                      "ehci_pci"
                      "nvme"
                      "uhci_hcd"
                    ];
                    network = {
                      enable = true;
                      ssh = {
                        enable = true;
                        ignoreEmptyHostKeys = true;
                        port = 22;
                        authorizedKeys = [ sshKey ];
                      };
                    };
                    supportedFilesystems = {
                      btrfs = true;
                      vfat = true;
                      zfs = lib.mkForce false;
                    };
                    systemd = {
                      emergencyAccess = true;
                      enable = true;
                      root = "gpt-auto";
                      tpm2.enable = true;
                    };
                    verbose = false;
                  };
                  kernelPackages = pkgs.linuxPackages_latest;
                  loader = {
                    efi.canTouchEfiVariables = true;
                    systemd-boot = {
                      configurationLimit = 10;
                      enable = true;
                    };
                  };
                  supportedFilesystems.zfs = lib.mkForce false;
                };

                disko.devices = {
                  disk = {
                    main = {
                      device = diskDevice;
                      type = "disk";
                      content = {
                        type = "gpt";
                        partitions = {
                          ESP = {
                            size = "1G";
                            type = "EF00";
                            content = {
                              type = "filesystem";
                              format = "vfat";
                              mountpoint = "/boot";
                              mountOptions = [
                                "noatime"
                                "umask=0077"
                              ];
                              extraArgs = [
                                "-n"
                                "ESP"
                              ];
                            };
                          };
                          root = {
                            size = "100%";
                            content = {
                              type = "filesystem";
                              format = "btrfs";
                              mountOptions = [
                                "autodefrag"
                                "compress=zstd:15"
                                "discard=async"
                                "noatime"
                              ];
                              mountpoint = "/";
                              extraArgs = [
                                "--label"
                                "root"
                              ];
                            };
                          };
                        };
                      };
                    };
                  };
                };

                documentation = {
                  doc.enable = false;
                  man.enable = false;
                  nixos.enable = false;
                };

                networking = {
                  extraHosts = ''
                    ${ipAddress} ${fqdn}
                  '';
                  firewall = {
                    enable = true;
                    allowedTCPPorts = [
                      22
                      80
                      443
                      2379
                      2380
                      6443
                    ];
                    allowedUDPPorts = [
                      8285
                      8472
                    ];
                    interfaces.flannelnet.allowedTCPPorts = [ 53 ];
                    interfaces.flannelnet.allowedUDPPorts = [ 53 ];
                  };
                  hostName = hostName;
                  networkmanager.enable = lib.mkForce false;
                  useNetworkd = true;
                  dhcpcd.enable = lib.mkForce false;
                  useDHCP = lib.mkForce false;
                };

                nix = {
                  settings = {
                    experimental-features = [
                      "nix-command"
                      "flakes"
                    ];
                    # extra-sandbox-paths = [ "/var/cache/ccache" ];
                    substituters = [
                      "https://cache.nixos.org?priority=40"
                      "https://nix-community.cachix.org?priority=41"
                      "https://numtide.cachix.org?priority=42"
                      # "https://attic.batonac.com/k3s?priority=43"
                    ];
                    trusted-public-keys = [
                      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
                      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
                      "numtide.cachix.org-1:2ps1kLBUWjxIneOy1Ik6cQjb41X0iXVXeHigGmycPPE="
                      "k3s:A8GYNJNy2p/ZMtxVlKuy1nZ8bnZ84PVfqPO6kg6A6qY="
                    ];
                    trusted-users = [
                      "root"
                      "nixos"
                      "@wheel"
                    ];
                  };
                  gc = {
                    automatic = true;
                    dates = "weekly";
                    options = "-d";
                  };
                };

                time.timeZone = timeZone;

                i18n.defaultLocale = locale;

                users.users = {
                  ${username} =
                    { pkgs, ... }:
                    {
                      extraGroups = [
                        "wheel"
                        "kubernetes"
                      ];
                      initialPassword = initialPassword;
                      isNormalUser = true;
                      openssh.authorizedKeys.keys = [ sshKey ];
                    };
                  root = {
                    openssh.authorizedKeys.keys = [ sshKey ];
                  };
                };

                age.secrets = {
                  cloudflare-email = {
                    file = ./secrets/cloudflare-email.age;
                    mode = "0400";
                    owner = "root";
                    group = "root";
                  };
                  cloudflare-dns-api-token = {
                    file = ./secrets/cloudflare-dns-api-token.age;
                    mode = "0400";
                    owner = "root";
                    group = "root";
                  };

                  # Internal Kubernetes PKI (generate .age files via generate-internal-pki.sh)
                  k8s-ca-crt = {
                    file = ./secrets/k8s-ca.crt.age;
                    #path = "/var/lib/kubernetes/pki/ca.crt";
                    owner = "root";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-ca-key = {
                    file = ./secrets/k8s-ca.key.age;
                    #path = "/var/lib/kubernetes/pki/ca.key";
                    owner = "root";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-apiserver-crt = {
                    file = ./secrets/k8s-apiserver.crt.age;
                    #path = "/var/lib/kubernetes/pki/apiserver.crt";
                    owner = "root";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-apiserver-key = {
                    file = ./secrets/k8s-apiserver.key.age;
                    #path = "/var/lib/kubernetes/pki/apiserver.key";
                    owner = "root";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-admin-crt = {
                    file = ./secrets/k8s-admin.crt.age;
                    #path = "/var/lib/kubernetes/pki/admin.crt";
                    owner = "root";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-admin-key = {
                    file = ./secrets/k8s-admin.key.age;
                    #path = "/var/lib/kubernetes/pki/admin.key";
                    owner = "root";
                    group = "kubernetes";
                    mode = "0440";
                  };

                  # etcd dedicated PKI (generated via generate-internal-pki.sh)
                  etcd-ca-crt = {
                    file = ./secrets/etcd-ca.crt.age;
                    #path = "/var/lib/etcd/pki/ca.crt";
                    owner = "etcd";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  etcd-ca-key = {
                    file = ./secrets/etcd-ca.key.age;
                    #path = "/var/lib/etcd/pki/ca.key";
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                  };
                  etcd-server-crt = {
                    file = ./secrets/etcd-server.crt.age;
                    #path = "/var/lib/etcd/pki/server.crt";
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                  };
                  etcd-server-key = {
                    file = ./secrets/etcd-server.key.age;
                    #path = "/var/lib/etcd/pki/server.key";
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                  };
                  etcd-peer-crt = {
                    file = ./secrets/etcd-peer.crt.age;
                    #path = "/var/lib/etcd/pki/peer.crt";
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                  };
                  etcd-peer-key = {
                    file = ./secrets/etcd-peer.key.age;
                    #path = "/var/lib/etcd/pki/peer.key";
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                  };
                  etcd-apiserver-client-crt = {
                    file = ./secrets/etcd-apiserver-client.crt.age;
                    #path = "/var/lib/etcd/pki/apiserver-client.crt";
                    owner = "etcd";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  etcd-apiserver-client-key = {
                    file = ./secrets/etcd-apiserver-client.key.age;
                    #path = "/var/lib/etcd/pki/apiserver-client.key";
                    owner = "etcd";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  etcd-flannel-client-crt = {
                    file = ./secrets/etcd-flannel-client.crt.age;
                    #path = "/var/lib/etcd/pki/flannel-client.crt";
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                  };
                  etcd-flannel-client-key = {
                    file = ./secrets/etcd-flannel-client.key.age;
                    #path = "/var/lib/etcd/pki/flannel-client.key";
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                  };

                  # Service account keys
                  k8s-service-account-crt = {
                    file = ./secrets/k8s-service-account.crt.age;
                    #path = "/var/lib/kubernetes/pki/service-account.crt";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-service-account-key = {
                    file = ./secrets/k8s-service-account.key.age;
                    #path = "/var/lib/kubernetes/pki/service-account.key";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };

                  # Kubelet server certificates
                  k8s-kubelet-server-crt = {
                    file = ./secrets/k8s-kubelet-server.crt.age;
                    #path = "/var/lib/kubernetes/pki/kubelet-server.crt";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-kubelet-server-key = {
                    file = ./secrets/k8s-kubelet-server.key.age;
                    #path = "/var/lib/kubernetes/pki/kubelet-server.key";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };

                  # Kubeconfig files
                  k8s-admin-kubeconfig = {
                    file = ./secrets/k8s-admin.kubeconfig.age;
                    path = "/etc/kubernetes/admin.kubeconfig";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };

                  # Component certificates
                  k8s-controller-manager-crt = {
                    file = ./secrets/k8s-controller-manager.crt.age;
                    #path = "/var/lib/kubernetes/pki/controller-manager.crt";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-controller-manager-key = {
                    file = ./secrets/k8s-controller-manager.key.age;
                    #path = "/var/lib/kubernetes/pki/controller-manager.key";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-scheduler-crt = {
                    file = ./secrets/k8s-scheduler.crt.age;
                    #path = "/var/lib/kubernetes/pki/scheduler.crt";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-scheduler-key = {
                    file = ./secrets/k8s-scheduler.key.age;
                    #path = "/var/lib/kubernetes/pki/scheduler.key";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-proxy-crt = {
                    file = ./secrets/k8s-proxy.crt.age;
                    #path = "/var/lib/kubernetes/pki/proxy.crt";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-proxy-key = {
                    file = ./secrets/k8s-proxy.key.age;
                    #path = "/var/lib/kubernetes/pki/proxy.key";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-kubelet-crt = {
                    file = ./secrets/k8s-kubelet.crt.age;
                    #path = "/var/lib/kubernetes/pki/kubelet.crt";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-kubelet-key = {
                    file = ./secrets/k8s-kubelet.key.age;
                    #path = "/var/lib/kubernetes/pki/kubelet.key";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };

                  # Component kubeconfig files
                  k8s-controller-manager-kubeconfig = {
                    file = ./secrets/k8s-controller-manager.kubeconfig.age;
                    path = "/etc/kubernetes/controller-manager.kubeconfig";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-scheduler-kubeconfig = {
                    file = ./secrets/k8s-scheduler.kubeconfig.age;
                    path = "/etc/kubernetes/scheduler.kubeconfig";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-proxy-kubeconfig = {
                    file = ./secrets/k8s-proxy.kubeconfig.age;
                    path = "/etc/kubernetes/proxy.kubeconfig";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                  k8s-kubelet-kubeconfig = {
                    file = ./secrets/k8s-kubelet.kubeconfig.age;
                    path = "/etc/kubernetes/kubelet.kubeconfig";
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                  };
                };

                environment = {
                  etc = {
                    "cni/net.d/10-crio-bridge.conflist".enable = false;
                    "cni/net.d/99-loopback.conflist".enable = false;
                  };

                  # Set system-wide KUBECONFIG to agenix-decrypted admin kubeconfig
                  variables = {
                    KUBECONFIG = "/etc/kubernetes/admin.kubeconfig";
                  };

                  systemPackages = extraPackages ++ [ agenix.packages.x86_64-linux.default ];
                };

                services = {
                  etcd = {
                    advertiseClientUrls = [ "https://${ipAddress}:2379" ];
                    # Remove the discovery line - it's for dynamic discovery, not needed for static cluster
                    # discovery = "https://${fqdn}:2380";
                    enable = true;
                    initialAdvertisePeerUrls = [ "https://${ipAddress}:2380" ];
                    initialCluster = [ "${hostName}=https://${ipAddress}:2380" ];
                    initialClusterState = "new";
                    listenClientUrls = [
                      "https://127.0.0.1:2379"
                      "https://${ipAddress}:2379"
                    ];
                    listenPeerUrls = [
                      "https://127.0.0.1:2380"
                      "https://${ipAddress}:2380"
                    ];
                    name = hostName;
                    openFirewall = true;
                    certFile = config.age.secrets.etcd-server-crt.path;
                    keyFile = config.age.secrets.etcd-server-key.path;
                    trustedCaFile = config.age.secrets.etcd-ca-crt.path;
                    peerCertFile = config.age.secrets.etcd-peer-crt.path;
                    peerKeyFile = config.age.secrets.etcd-peer-key.path;
                    peerTrustedCaFile = config.age.secrets.etcd-ca-crt.path;
                    clientCertAuth = true;
                    peerClientCertAuth = true;
                  };
                  flannel = {
                    enable = true;
                    network = "10.42.0.0/16";
                    backend = {
                      type = "vxlan";
                      port = 8472;
                    };
                    iface = "ens18";
                    storageBackend = lib.mkForce "etcd";
                    etcd = {
                      endpoints = [ "https://${fqdn}:2379" ];
                      caFile = config.age.secrets.etcd-ca-crt.path;
                      certFile = config.age.secrets.etcd-flannel-client-crt.path;
                      keyFile = config.age.secrets.etcd-flannel-client-key.path;
                    };
                  };
                  kubernetes = {

                    apiserverAddress = "https://${fqdn}:6443";
                    caFile = "/var/lib/acme/${fqdn}/chain.pem";
                    clusterCidr = "10.42.0.0/16";
                    easyCerts = false;
                    masterAddress = fqdn;
                    roles = [
                      "master"
                      "node"
                    ];

                    apiserver = {
                      advertiseAddress = ipAddress;
                      allowPrivileged = true;
                      authorizationMode = [
                        "Node"
                        "RBAC"
                      ];
                      bindAddress = "0.0.0.0";
                      enable = true;
                      securePort = 6443;
                      serviceClusterIpRange = "10.43.0.0/16";
                      serviceAccountKeyFile = config.age.secrets.k8s-service-account-crt.path;
                      serviceAccountSigningKeyFile = config.age.secrets.k8s-service-account-key.path;
                      tlsCertFile = config.age.secrets.k8s-apiserver-crt.path;
                      tlsKeyFile = config.age.secrets.k8s-apiserver-key.path;
                      etcd = {
                        servers = [ "https://${fqdn}:2379" ];
                        caFile = config.age.secrets.etcd-ca-crt.path;
                        certFile = config.age.secrets.etcd-apiserver-client-crt.path;
                        keyFile = config.age.secrets.etcd-apiserver-client-key.path;
                      };
                      clientCaFile = config.age.secrets.k8s-ca-crt.path;
                    };

                    controllerManager = {
                      enable = true;
                      bindAddress = "0.0.0.0";
                      clusterCidr = "10.42.0.0/16";
                      rootCaFile = config.age.secrets.k8s-ca-crt.path;
                      serviceAccountKeyFile = config.age.secrets.k8s-service-account-key.path; # ✅ Use PRIVATE key for signing
                      kubeconfig = {
                        caFile = config.age.secrets.k8s-ca-crt.path;
                        certFile = config.age.secrets.k8s-controller-manager-crt.path;
                        keyFile = config.age.secrets.k8s-controller-manager-key.path;
                        server = "https://${fqdn}:6443";
                      };
                    };

                    kubeconfig = {
                      caFile = config.age.secrets.k8s-ca-crt.path;
                      certFile = config.age.secrets.k8s-admin-crt.path;
                      keyFile = config.age.secrets.k8s-admin-key.path;
                      server = "https://${fqdn}:6443";
                    };

                    kubelet = {
                      containerRuntimeEndpoint = "unix:///run/crio/crio.sock";
                      kubeconfig = {
                        caFile = config.age.secrets.k8s-ca-crt.path;
                        certFile = config.age.secrets.k8s-kubelet-crt.path;
                        keyFile = config.age.secrets.k8s-kubelet-key.path;
                        server = "https://${fqdn}:6443";
                      };
                      tlsCertFile = config.age.secrets.k8s-kubelet-server-crt.path;
                      tlsKeyFile = config.age.secrets.k8s-kubelet-server-key.path;
                      cni = {
                        packages = with pkgs; [
                          cni-plugins
                          cni-plugin-flannel
                        ];
                        config = [
                          {
                            name = "flannelnet";
                            type = "flannel";
                            cniVersion = pkgs.cni-plugin-flannel.version;
                            delegate = {
                              isDefaultGateway = true;
                              bridge = "flannelnet";
                            };
                          }
                        ];
                      };
                    };

                    proxy = {
                      enable = true;
                      kubeconfig = {
                        caFile = config.age.secrets.k8s-ca-crt.path;
                        certFile = config.age.secrets.k8s-proxy-crt.path;
                        keyFile = config.age.secrets.k8s-proxy-key.path;
                        server = "https://${fqdn}:6443";
                      };
                    };

                    addons = {
                      dns = {
                        enable = true;
                      };
                    };

                    scheduler = {
                      enable = true;
                      address = "0.0.0.0";
                      port = 10251;
                      kubeconfig = {
                        caFile = config.age.secrets.k8s-ca-crt.path;
                        certFile = config.age.secrets.k8s-scheduler-crt.path;
                        keyFile = config.age.secrets.k8s-scheduler-key.path;
                        server = "https://${fqdn}:6443";
                      };
                    };

                  };

                  lvm.enable = false;

                  openssh = {
                    enable = true;
                    settings = {
                      PermitRootLogin = "yes";
                    };
                  };

                  vscode-server.enable = true;
                };

                programs = {
                  nix-ld.enable = true;
                };

                security = {
                  acme = {
                    acceptTerms = true;
                    defaults.email = "kevin@avu.nu";
                    certs."${fqdn}" = {
                      domain = fqdn;
                      dnsProvider = "cloudflare";
                      credentialFiles = {
                        "CLOUDFLARE_EMAIL_FILE" = config.age.secrets.cloudflare-email.path;
                        "CLOUDFLARE_DNS_API_TOKEN_FILE" = config.age.secrets.cloudflare-dns-api-token.path;
                      };
                      group = "kubernetes";
                      webroot = null;
                    };
                  };
                };

                system.stateVersion = stateVersion;

                systemd = {
                  network = {
                    enable = true;
                    networks."10-wan" = {
                      matchConfig.Name = "ens18";
                      address = [
                        # configure addresses including subnet mask
                        "${ipAddress}/24"
                      ];
                      routes = [
                        # create default routes for IPv4
                        { Gateway = "10.48.4.1"; }
                      ];
                      networkConfig = {
                        IPv6AcceptRA = true;
                      };
                      linkConfig.RequiredForOnline = "routable";
                    };
                  };

                  # Create .kube directory for kubernetes user with proper permissions
                  tmpfiles.rules = [
                    "d /var/lib/kubernetes/.kube 0750 kubernetes kubernetes -"
                    "L+ /var/lib/kubernetes/.kube/config - - - - /etc/kubernetes/admin.kubeconfig"
                    "L+ /var/lib/kubernetes/.kube/kuberc - - - - /etc/kubernetes/admin.kubeconfig"
                  ];

                  # Add services to kubernetes/etcd groups for certificate access
                  services = {
                    etcd.serviceConfig.SupplementaryGroups = [
                      "kubernetes"
                      "etcd"
                    ];
                    flannel.serviceConfig.SupplementaryGroups = [
                      "kubernetes"
                      "etcd"
                    ];

                    # Ensure Kubernetes services can read their certificates
                    kube-apiserver.serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                    kube-controller-manager.serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                    kube-scheduler.serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                    kube-proxy.serviceConfig.SupplementaryGroups = [ "kubernetes" ];

                    # Kubelet must wait for Flannel to write CNI config
                    kubelet = {
                      serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                      requires = [ "flannel.service" ];
                      after = [ "flannel.service" ];
                    };
                  };
                };

                virtualisation = {
                  containers = {
                    enable = true;
                  };
                  cri-o = {
                    enable = true;
                    storageDriver = "btrfs";
                    runtime = "crun";
                    settings = {
                      crio = {
                        image = {
                          # Configure default registries
                          registries = {
                            "docker.io" = {
                              blocked = false;
                              insecure = false;
                              location = "docker.io";
                              mirror = [ ];
                              prefix = "docker.io";
                            };
                            "quay.io" = {
                              blocked = false;
                              insecure = false;
                              location = "quay.io";
                              mirror = [ ];
                              prefix = "quay.io";
                            };
                            "gcr.io" = {
                              blocked = false;
                              insecure = false;
                              location = "gcr.io";
                              mirror = [ ];
                              prefix = "gcr.io";
                            };
                            "registry.k8s.io" = {
                              blocked = false;
                              insecure = false;
                              location = "registry.k8s.io";
                              mirror = [ ];
                              prefix = "registry.k8s.io";
                            };
                          };
                        };
                        network = {
                          plugin_dirs = [
                            "${pkgs.cni-plugins}/bin"
                            "${pkgs.cni-plugin-flannel}/bin"
                          ];
                          network_dir = "/etc/cni/net.d";
                        };
                        runtime = {
                          cgroup_manager = "systemd";
                          default_runtime = "crun";
                          pause_image = "rancher/mirrored-pause:3.6";
                          pause_image_auth_file = "";
                          pause_command = "/pause";
                          conmon_cgroup = "pod";
                          manage_ns_lifecycle = true;
                        };
                      };
                    };
                  };
                };
              }
            )
          ];
        };
      };
    };
}
