#!/bin/bash
mkdir -p secrets/initrd
ssh-keygen -t ed25519 -f secrets/initrd/ssh_host_ed25519_key -N "" -C "initrd@k3s-dev"
chmod 600 secrets/initrd/ssh_host_ed25519_key
chmod 644 secrets/initrd/ssh_host_ed25519_key.pub
