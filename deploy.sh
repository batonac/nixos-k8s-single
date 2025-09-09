#!/bin/sh
nix run github:nix-community/nixos-anywhere -- --flake .#k3s-dev --target-host root@k3s-dev.batonac.com