#!/bin/sh
source ./.env
nixos-rebuild switch --flake .#k3s-dev --target-host "root@k3s-dev.batonac.com" --impure