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
    agenix-rekey = {
      url = "github:oddlama/agenix-rekey";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    juicefs-csi-driver = {
      url = "github:juicedata/juicefs-csi-driver";
      flake = false;
    };
    flox = {
      url = "github:flox/flox/latest";
      # inputs.nixpkgs.follows = "nixpkgs";
    };

    # # Your private secrets repo - this is fine!
    # secrets = {
    #   url = "git+ssh://git@github.com/yourusername/nixos-k8s-secrets";
    #   flake = false;  # Not a flake itself, just a source repo
    # };
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      disko,
      vscode-server,
      kubenix,
      agenix,
      agenix-rekey,
      # secrets,
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
      system = "x86_64-linux";
      extraPackages = with nixpkgs.legacyPackages.${system}; [
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
      packages.${system}.kubenix-manifests =
        (kubenix.evalModules.${system} {
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

      # Expose agenix-rekey configuration
      agenix-rekey = agenix-rekey.configure {
        userFlake = self;
        nixosConfigurations = self.nixosConfigurations;
      };

      # Development shell with agenix-rekey
      devShells.${system}.default = nixpkgs.legacyPackages.${system}.mkShell {
        buildInputs = with nixpkgs.legacyPackages.${system}; [
          agenix-rekey.packages.${system}.default
          age
          age-plugin-yubikey
          bitwarden-cli
          nixfmt-rfc-style
          openssh
          openssl
          ssh-to-age
        ];

        shellHook = ''
          echo "🔐 NixOS K8s Secrets Management Shell (with agenix-rekey)"
          echo ""
          echo "Available tools:"
          echo "  agenix       - Manage and rekey secrets"
          echo "  age          - Age encryption tool"
          echo ""
          echo "YubiKey workflow:"
          echo "  1. Generate YubiKey identity: age-plugin-yubikey --generate"
          echo "  2. Store identity in ./secrets/yubikey-identity.pub"
          echo "  3. Edit secrets: agenix edit secrets/my-secret.age"
          echo "  4. Rekey for hosts: agenix rekey -a"
          echo ""
        '';
      };

      nixosConfigurations = {
        "${hostName}" = nixpkgs.lib.nixosSystem {
          system = "${system}";
          modules = [
            { nix.nixPath = [ "nixpkgs=${self.inputs.nixpkgs}" ]; }
            vscode-server.nixosModules.default
            disko.nixosModules.disko
            agenix.nixosModules.default
            agenix-rekey.nixosModules.default
            ./addons/default.nix
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
                        port = 22;
                        authorizedKeys = [ sshKey ];
                        # Use the initrd key from the secrets submodule
                        hostKeys = [ "/secrets/initrd/ssh_host_ed25519_key" ];
                      };
                    };
                    # Copy the SSH host key from flake input into initrd
                    secrets = {
                      "/secrets/initrd/ssh_host_ed25519_key" = "/etc/ssh/ssh_host_ed25519_key";
                    };
                    supportedFilesystems = {
                      ext4 = true;
                      vfat = true;
                      zfs = lib.mkForce false;
                    };
                    systemd = {
                      emergencyAccess = true;
                      enable = true;
                      root = "gpt-auto";
                      tpm2.enable = true;
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
                              format = "ext4";
                              mountOptions = [
                                "noatime"
                              ];
                              mountpoint = "/";
                              extraArgs = [
                                "-L"
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

                # Configure agenix-rekey
                age.rekey = {
                  # Host SSH public key
                  hostPubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEiNCbMBi8L9Kq1/8H+vWSSH6Vm9saENQcWa6lTCIIj8"; # REPLACE AFTER FIRST BOOT

                  # Your YubiKey identity
                  masterIdentities = [ ./secrets/yubikey-identity.pub ];

                  # Use local storage mode (simpler, more flexible)
                  storageMode = "local";
                  localStorageDir = ./. + "/secrets/rekeyed/${config.networking.hostName}";

                  # Optional: Directory for generated secrets
                  generatedSecretsDir = ./secrets/generated;
                };

                age.secrets = {
                  # Cloudflare secrets
                  cloudflare-email = {
                    rekeyFile = ./secrets/cloudflare-email.age;
                    mode = "0400";
                    owner = "root";
                    group = "root";
                  };
                  cloudflare-dns-api-token = {
                    rekeyFile = ./secrets/cloudflare-dns-api-token.age;
                    mode = "0400";
                    owner = "root";
                    group = "root";
                  };

                  # Kubernetes PKI - all with generators!
                  k8s-ca-crt = {
                    rekeyFile = ./secrets/k8s-ca.crt.age;
                    owner = "root";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase"; # Example generator
                  };
                  k8s-ca-key = {
                    rekeyFile = ./secrets/k8s-ca.key.age;
                    owner = "root";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-apiserver-crt = {
                    rekeyFile = ./secrets/k8s-apiserver.crt.age;
                    owner = "root";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-apiserver-key = {
                    rekeyFile = ./secrets/k8s-apiserver.key.age;
                    owner = "root";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-admin-crt = {
                    rekeyFile = ./secrets/k8s-admin.crt.age;
                    owner = "root";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-admin-key = {
                    rekeyFile = ./secrets/k8s-admin.key.age;
                    owner = "root";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };

                  # etcd dedicated PKI (generated via generate-internal-pki.sh)
                  etcd-ca-crt = {
                    rekeyFile = ./secrets/etcd-ca.crt.age;
                    owner = "etcd";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  etcd-ca-key = {
                    rekeyFile = ./secrets/etcd-ca.key.age;
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  etcd-server-crt = {
                    rekeyFile = ./secrets/etcd-server.crt.age;
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  etcd-server-key = {
                    rekeyFile = ./secrets/etcd-server.key.age;
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  etcd-peer-crt = {
                    rekeyFile = ./secrets/etcd-peer.crt.age;
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  etcd-peer-key = {
                    rekeyFile = ./secrets/etcd-peer.key.age;
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  etcd-apiserver-client-crt = {
                    rekeyFile = ./secrets/etcd-apiserver-client.crt.age;
                    owner = "etcd";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  etcd-apiserver-client-key = {
                    rekeyFile = ./secrets/etcd-apiserver-client.key.age;
                    owner = "etcd";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  etcd-flannel-client-crt = {
                    rekeyFile = ./secrets/etcd-flannel-client.crt.age;
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  etcd-flannel-client-key = {
                    rekeyFile = ./secrets/etcd-flannel-client.key.age;
                    owner = "etcd";
                    group = "etcd";
                    mode = "0440";
                    generator.script = "passphrase";
                  };

                  # Service account keys
                  k8s-service-account-crt = {
                    rekeyFile = ./secrets/k8s-service-account.crt.age;
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-service-account-key = {
                    rekeyFile = ./secrets/k8s-service-account.key.age;
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };

                  # Kubelet server certificates
                  k8s-kubelet-server-crt = {
                    rekeyFile = ./secrets/k8s-kubelet-server.crt.age;
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-kubelet-server-key = {
                    rekeyFile = ./secrets/k8s-kubelet-server.key.age;
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
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
                    rekeyFile = ./secrets/k8s-controller-manager.crt.age;
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-controller-manager-key = {
                    rekeyFile = ./secrets/k8s-controller-manager.key.age;
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-scheduler-crt = {
                    rekeyFile = ./secrets/k8s-scheduler.crt.age;
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-scheduler-key = {
                    rekeyFile = ./secrets/k8s-scheduler.key.age;
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-proxy-crt = {
                    rekeyFile = ./secrets/k8s-proxy.crt.age;
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-proxy-key = {
                    rekeyFile = ./secrets/k8s-proxy.key.age;
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-kubelet-crt = {
                    rekeyFile = ./secrets/k8s-kubelet.crt.age;
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
                  };
                  k8s-kubelet-key = {
                    rekeyFile = ./secrets/k8s-kubelet.key.age;
                    owner = "kubernetes";
                    group = "kubernetes";
                    mode = "0440";
                    generator.script = "passphrase";
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

                  # No addon-manager certificates needed!
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

                  systemPackages = extraPackages ++ [
                    inputs.agenix.packages.${system}.default
                    inputs.agenix-rekey.packages.${system}.default
                    inputs.flox.packages.${system}.default
                  ];
                };

                services = {
                  etcd = {
                    advertiseClientUrls = [
                      "https://${fqdn}:2379"
                      "https://${ipAddress}:2379"
                    ];
                    # Remove the discovery line - it's for dynamic discovery, not needed for static cluster
                    # discovery = "https://${fqdn}:2380";
                    enable = true;
                    initialAdvertisePeerUrls = [ "https://${ipAddress}:2380" ];
                    initialCluster = [ "${hostName}=https://${ipAddress}:2380" ];
                    initialClusterState = "new";
                    listenClientUrls = [
                      "https://${ipAddress}:2379"
                      "https://127.0.0.1:2379"
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
                    # Use kubernetes backend instead of etcd - this is the standard way
                    storageBackend = "kubernetes";
                    # When using kubernetes backend, flannel needs a kubeconfig
                    kubeconfig = config.age.secrets.k8s-admin-kubeconfig.path;
                    nodeName = hostName;
                  };
                  kubernetes = {

                    # Enable addon manager to handle RBAC bootstrap
                    addonManager = {
                      enable = true;
                      # bootstrapAddons are now managed by ./addons/default.nix
                      # addons are also managed by ./addons/default.nix
                    };

                    apiserverAddress = "https://${fqdn}:6443";
                    caFile = config.age.secrets.k8s-ca-crt.path; # changed from "/var/lib/acme/${fqdn}/chain.pem";
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
                        servers = [ "https://${ipAddress}:2379" ];
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
                      serviceAccountKeyFile = config.age.secrets.k8s-service-account-key.path;
                      kubeconfig = {
                        caFile = config.age.secrets.k8s-ca-crt.path;
                        certFile = config.age.secrets.k8s-controller-manager-crt.path;
                        keyFile = config.age.secrets.k8s-controller-manager-key.path;
                        server = "https://${fqdn}:6443";
                      };
                      # Add extraOpts to suppress warnings about authentication/authorization
                      extraOpts = ''
                        --authentication-kubeconfig=/etc/kubernetes/controller-manager.kubeconfig
                        --authorization-kubeconfig=/etc/kubernetes/controller-manager.kubeconfig
                      '';
                    };

                    kubeconfig = {
                      caFile = config.age.secrets.k8s-ca-crt.path;
                      certFile = config.age.secrets.k8s-admin-crt.path;
                      keyFile = config.age.secrets.k8s-admin-key.path;
                      server = "https://${fqdn}:6443";
                    };

                    kubelet = {
                      containerRuntimeEndpoint = "unix:///run/containerd/containerd.sock";
                      enable = true;
                      hostname = hostName;
                      clusterDns = [ "10.43.0.254" ];
                      # Explicitly tell kubelet we're using containerd
                      extraOpts = ''
                        --runtime-cgroups=/system.slice/containerd.service
                      '';
                      kubeconfig = {
                        caFile = config.age.secrets.k8s-ca-crt.path;
                        certFile = config.age.secrets.k8s-kubelet-crt.path;
                        keyFile = config.age.secrets.k8s-kubelet-key.path;
                        server = "https://${fqdn}:6443";
                      };
                      tlsCertFile = config.age.secrets.k8s-kubelet-server-crt.path;
                      tlsKeyFile = config.age.secrets.k8s-kubelet-server-key.path;
                      # Remove the hardcoded CNI config - let flannel module manage it
                      # The flannel module sets this automatically when enabled
                      # cni = {
                      #   packages = with pkgs; [
                      #     cni-plugins
                      #     cni-plugin-flannel
                      #   ];
                      #   config = [
                      #     {
                      #       name = "flannelnet";
                      #       type = "flannel";
                      #       cniVersion = pkgs.cni-plugin-flannel.version;
                      #       delegate = {
                      #         isDefaultGateway = true;
                      #         bridge = "flannelnet";
                      #       };
                      #     }
                      #   ];
                      # };
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
                      # Add extraOpts to suppress warnings
                      extraOpts = ''
                        --authentication-kubeconfig=/etc/kubernetes/scheduler.kubeconfig
                        --authorization-kubeconfig=/etc/kubernetes/scheduler.kubeconfig
                      '';
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

                  tmpfiles.rules = [
                    "d /var/lib/kubernetes/.kube 0750 kubernetes kubernetes -"
                    "L+ /var/lib/kubernetes/.kube/config - - - - /etc/kubernetes/admin.kubeconfig"
                    "L+ /var/lib/kubernetes/.kube/kuberc - - - - /etc/kubernetes/admin.kubeconfig"
                  ];

                  services = {
                    etcd.serviceConfig.SupplementaryGroups = [
                      "kubernetes"
                      "etcd"
                    ];
                    flannel.serviceConfig.SupplementaryGroups = [
                      "kubernetes"
                      "etcd"
                    ];

                    kube-apiserver = {
                      serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                      requires = [ "etcd.service" ];
                      after = [ "etcd.service" ];
                    };
                    kube-controller-manager.serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                    kube-scheduler.serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                    kube-proxy.serviceConfig.SupplementaryGroups = [ "kubernetes" ];

                    kubelet = {
                      serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                      requires = [
                        "flannel.service"
                        "containerd.service"
                        "install-flox-shim.service"
                      ];
                      after = [
                        "flannel.service"
                        "containerd.service"
                        "install-flox-shim.service"
                      ];
                    };

                    # Configure addon-manager to use admin kubeconfig
                    kube-addon-manager = {
                      environment.KUBECONFIG = config.age.secrets.k8s-admin-kubeconfig.path;
                      serviceConfig.SupplementaryGroups = [ "kubernetes" ];

                      # The preStart needs cluster-admin rights for bootstrapAddons
                      serviceConfig.PermissionsStartOnly = true;

                      preStart =
                        with pkgs;
                        lib.mkIf (config.services.kubernetes.addonManager.bootstrapAddons != { }) (
                          let
                            files = lib.mapAttrsToList (
                              n: v: pkgs.writeText "${n}.json" (builtins.toJSON v)
                            ) config.services.kubernetes.addonManager.bootstrapAddons;
                          in
                          ''
                            export KUBECONFIG=${config.age.secrets.k8s-admin-kubeconfig.path}
                            ${pkgs.kubernetes}/bin/kubectl apply -f ${lib.concatStringsSep " \\\n -f " files}
                          ''
                        );
                    };

                    # Install containerd-shim-flox using Flox
                    install-flox-shim = {
                      description = "Install containerd-shim-flox runtime";
                      wantedBy = [ "multi-user.target" ];
                      before = [ "containerd.service" ];
                      path = with pkgs; [
                        inputs.flox.packages.${system}.default
                        coreutils
                        gnutar
                        gzip
                      ];
                      serviceConfig = {
                        Type = "oneshot";
                        RemainAfterExit = true;
                      };
                      script = ''
                        # Try automatic installation first
                        echo "Attempting automatic Flox shim installation..."
                        ${inputs.flox.packages.${system}.default}/bin/flox activate -r flox/containerd-shim-flox-installer --trust || {
                          echo "Automatic installation failed or not available, using manual method..."
                          
                          # Manual installation fallback
                          mkdir -p /var/lib/flox/containerd-shim
                          cd /var/lib/flox/containerd-shim
                          
                          # Initialize flox environment if not already done
                          if [ ! -d ".flox" ]; then
                            ${inputs.flox.packages.${system}.default}/bin/flox init -b
                            # Install the containerd-shim-flox package
                            # Try version 2.x first (for containerd 2.x), fall back to 1.7
                            ${inputs.flox.packages.${system}.default}/bin/flox install containerd-shim-flox-2x || \
                              ${inputs.flox.packages.${system}.default}/bin/flox install containerd-shim-flox-17
                          fi
                          
                          # Create symlink to /usr/local/bin if shim exists
                          mkdir -p /usr/local/bin
                          if [ -f ".flox/run/x86_64-linux.containerd-shim-flox.run/bin/containerd-shim-flox-v2" ]; then
                            ln -sf /var/lib/flox/containerd-shim/.flox/run/x86_64-linux.containerd-shim-flox.run/bin/containerd-shim-flox-v2 \
                              /usr/local/bin/containerd-shim-flox-v2
                            echo "Flox shim installed successfully at /usr/local/bin/containerd-shim-flox-v2"
                          else
                            echo "Warning: Flox shim binary not found after installation"
                          fi
                        }
                        
                        # Verify installation
                        if [ -x "/usr/local/bin/containerd-shim-flox-v2" ]; then
                          echo "Flox containerd shim is ready"
                        else
                          echo "Warning: Flox containerd shim not found or not executable"
                        fi
                      '';
                    };
                  };

                };

                virtualisation = {
                  containers = {
                    enable = true;
                  };
                  containerd = {
                    enable = true;
                    settings = {
                      version = 2;
                      plugins."io.containerd.grpc.v1.cri" = {
                        cni = {
                          bin_dir = "${pkgs.cni-plugins}/bin";
                          conf_dir = "/etc/cni/net.d";
                        };
                        containerd = {
                          default_runtime_name = "runc";
                          runtimes = {
                            runc = {
                              runtime_type = "io.containerd.runc.v2";
                              options = {
                                SystemdCgroup = true;
                              };
                            };
                            # Flox runtime configuration
                            flox = {
                              runtime_path = "/usr/local/bin/containerd-shim-flox-v2";
                              runtime_type = "io.containerd.runc.v2";
                              pod_annotations = [ "flox.dev/*" ];
                              container_annotations = [ "flox.dev/*" ];
                              options = {
                                SystemdCgroup = true;
                              };
                            };
                          };
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
