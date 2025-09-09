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
  };

  outputs =
    {
      self,
      nixpkgs,
      disko,
      vscode-server,
      kubenix,
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

      nixosConfigurations = {
        "${hostName}" = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            { nix.nixPath = [ "nixpkgs=${self.inputs.nixpkgs}" ]; }
            vscode-server.nixosModules.default
            disko.nixosModules.disko
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
                ];

                boot = {
                  initrd = {
                    availableKernelModules = [
                      "ahci"
                      "ehci_pci"
                      "nvme"
                      "uhci_hcd"
                    ];
                    supportedFilesystems.zfs = lib.mkForce false;
                    systemd = {
                      enable = true;
                      tpm2.enable = true;
                    };
                    verbose = false;
                    zfs.enabled = lib.mkForce false;
                  };
                  kernelPackages = pkgs.linuxPackages_latest;
                  loader = {
                    efi.canTouchEfiVariables = true;
                    systemd-boot = {
                      configurationLimit = 10;
                      enable = true;
                    };
                  };
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

                users.users.${username} =
                  { pkgs, ... }:
                  {
                    extraGroups = [
                      "wheel"
                      "kubernetes"
                    ];
                    initialPassword = initialPassword;
                    isNormalUser = true;
                    openssh.authorizedKeys.keys = [
                      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv4SpIhHJqtRaYBRQOin4PTDUxRwo7ozoQHTUFjMGLW avunu@AvunuCentral"
                    ];
                  };

                environment = {
                  etc = {
                    "cni/net.d/10-crio-bridge.conflist".enable = false;
                    "cni/net.d/99-loopback.conflist".enable = false;
                  };
                  systemPackages = extraPackages;
                };

                fileSystems = lib.mkForce {
                  "/" = {
                    device = "/dev/disk/by-label/root";
                    fsType = "f2fs";
                    options = [
                      "atgc"
                      "compress_algorithm=zstd"
                      "compress_chksum"
                      "gc_merge"
                      "noatime"
                    ];
                  };
                  "/boot" = {
                    device = "/dev/disk/by-label/ESP";
                    fsType = "vfat";
                    options = [
                      "noatime"
                      "umask=0077"
                    ];
                  };
                };

                services = {
                  etcd = {
                    advertiseClientUrls = [ "https://${fqdn}:2379" ];
                    # discovery = "https://${hostName}.batonac.com:2380";
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
                    certFile = "/var/lib/acme/${fqdn}/cert.pem";
                    keyFile = "/var/lib/acme/${fqdn}/key.pem";
                    trustedCaFile = "/var/lib/acme/${fqdn}/chain.pem";
                    # Peer certificates (for etcd cluster communication)
                    peerCertFile = "/var/lib/acme/${fqdn}/cert.pem";
                    peerKeyFile = "/var/lib/acme/${fqdn}/key.pem";
                    peerTrustedCaFile = "/var/lib/acme/${fqdn}/chain.pem";
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
                      caFile = "/var/lib/acme/${fqdn}/chain.pem";
                      certFile = "/var/lib/acme/${fqdn}/cert.pem";
                      keyFile = "/var/lib/acme/${fqdn}/key.pem";
                    };
                  };
                  kubernetes = {
                    addons = {
                      dns = {
                        enable = true;
                      };
                    };

                    # Enable addon manager for custom addons
                    addonManager = {
                      enable = true;
                      addons = {
                        # Namespaces
                        cert-manager-namespace = {
                          apiVersion = "v1";
                          kind = "Namespace";
                          metadata = {
                            name = "cert-manager";
                            labels = {
                              "addonmanager.kubernetes.io/mode" = "Reconcile";
                            };
                          };
                        };

                        juicefs-csi-namespace = {
                          apiVersion = "v1";
                          kind = "Namespace";
                          metadata = {
                            name = "juicefs-csi";
                            labels = {
                              "addonmanager.kubernetes.io/mode" = "Reconcile";
                            };
                          };
                        };

                        monitoring-namespace = {
                          apiVersion = "v1";
                          kind = "Namespace";
                          metadata = {
                            name = "monitoring";
                            labels = {
                              "addonmanager.kubernetes.io/mode" = "Reconcile";
                            };
                          };
                        };

                        # Test pod
                        alpine-test = {
                          apiVersion = "v1";
                          kind = "Pod";
                          metadata = {
                            name = "alpine-test";
                            namespace = "default";
                            labels = {
                              "addonmanager.kubernetes.io/mode" = "Reconcile";
                              app = "alpine-test";
                            };
                          };
                          spec = {
                            containers = [
                              {
                                name = "alpine";
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
                              }
                            ];
                            restartPolicy = "Always";
                          };
                        };

                        # Example nginx deployment
                        nginx-deployment = {
                          apiVersion = "apps/v1";
                          kind = "Deployment";
                          metadata = {
                            name = "nginx";
                            namespace = "default";
                            labels = {
                              "addonmanager.kubernetes.io/mode" = "Reconcile";
                              app = "nginx";
                            };
                          };
                          spec = {
                            replicas = 1;
                            selector = {
                              matchLabels = {
                                app = "nginx";
                              };
                            };
                            template = {
                              metadata = {
                                labels = {
                                  app = "nginx";
                                };
                              };
                              spec = {
                                containers = [
                                  {
                                    name = "nginx";
                                    image = "nginx:1.25";
                                    imagePullPolicy = "IfNotPresent";
                                    ports = [
                                      {
                                        containerPort = 80;
                                      }
                                    ];
                                  }
                                ];
                              };
                            };
                          };
                        };

                        # Service for nginx
                        nginx-service = {
                          apiVersion = "v1";
                          kind = "Service";
                          metadata = {
                            name = "nginx";
                            namespace = "default";
                            labels = {
                              "addonmanager.kubernetes.io/mode" = "Reconcile";
                              app = "nginx";
                            };
                          };
                          spec = {
                            selector = {
                              app = "nginx";
                            };
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

                    apiserver = {
                      advertiseAddress = ipAddress;
                      allowPrivileged = true;
                      authorizationMode = [ "AlwaysAllow" ];
                      bindAddress = "0.0.0.0";
                      clientCaFile = "/etc/kubernetes/client-certs/client-ca.crt";
                      enable = true;
                      securePort = 6443;
                      serviceClusterIpRange = "10.43.0.0/16";
                      serviceAccountKeyFile = "/var/lib/acme/${fqdn}/cert.pem";
                      serviceAccountSigningKeyFile = "/var/lib/acme/${fqdn}/key.pem";
                      tlsCertFile = "/var/lib/acme/${fqdn}/cert.pem";
                      tlsKeyFile = "/var/lib/acme/${fqdn}/key.pem";
                      etcd = {
                        servers = [ "https://${fqdn}:2379" ];
                        caFile = "/var/lib/acme/${fqdn}/chain.pem";
                        certFile = "/var/lib/acme/${fqdn}/cert.pem";
                        keyFile = "/var/lib/acme/${fqdn}/key.pem";
                      };
                    };

                    controllerManager = {
                      enable = true;
                      bindAddress = "0.0.0.0";
                      clusterCidr = "10.42.0.0/16";
                      rootCaFile = "/var/lib/acme/${fqdn}/chain.pem";
                      serviceAccountKeyFile = "/var/lib/acme/${fqdn}/key.pem";
                      tlsCertFile = "/var/lib/acme/${fqdn}/cert.pem";
                      tlsKeyFile = "/var/lib/acme/${fqdn}/key.pem";
                    };

                    scheduler = {
                      enable = true;
                      address = "0.0.0.0";
                      port = 10251;
                    };

                    apiserverAddress = "https://${fqdn}:6443";
                    caFile = "/var/lib/acme/${fqdn}/chain.pem";
                    clusterCidr = "10.42.0.0/16";
                    easyCerts = false;

                    kubeconfig = {
                      caFile = "/var/lib/acme/${fqdn}/chain.pem";
                      certFile = "/var/lib/acme/${fqdn}/cert.pem";
                      keyFile = "/var/lib/acme/${fqdn}/key.pem";
                      server = "https://${fqdn}:6443";
                    };

                    # Seed container images and kubelet config
                    kubelet = {
                      containerRuntimeEndpoint = "unix:///run/crio/crio.sock";
                      seedDockerImages = [
                        (pkgs.dockerTools.pullImage {
                          imageName = "coredns/coredns";
                          imageDigest = "sha256:a0ead06651cf580044aeb0a0feba63591858fb2e43ade8c9dea45a6a89ae7e5e";
                          finalImageTag = "1.10.1";
                          sha256 = "0wg696920smmal7552a2zdhfncndn5kfammfa8bk8l7dz9bhk0y1";
                        })
                        # (pkgs.dockerTools.pullImage {
                        #   imageName = "alpine";
                        #   finalImageTag = "latest";
                        #   sha256 = "sha256-6457d53fb065d6f250e1504b9bc42d5b6c65941d57532c072d929dd0628977d0";
                        # })
                        # (pkgs.dockerTools.pullImage {
                        #   imageName = "nginx";
                        #   finalImageTag = "1.25";
                        #   sha256 = "sha256-4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac";
                        # })
                      ];

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

                    masterAddress = fqdn;

                    roles = [
                      "master"
                      "node"
                    ];

                  };

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
                      dnsProvider = "cloudflare"; # or your DNS provider
                      credentialsFile = "/etc/nixos/secrets/cloudflare-credentials";
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
                        "10.48.4.181/24"
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

                  # Add services to kubernetes group for certificate access
                  services.etcd.serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                  services.flannel.serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                  services.kube-apiserver.serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                  services.kube-controller-manager.serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                  services.kube-scheduler.serviceConfig.SupplementaryGroups = [ "kubernetes" ];
                  services.kube-addon-manager.serviceConfig.SupplementaryGroups = [ "kubernetes" ];
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
