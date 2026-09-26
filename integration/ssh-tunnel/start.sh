#!/bin/sh
set -eu
umask 077
cp /secrets/id_ed25519 /run/tunnel/id_ed25519
chmod 600 /run/tunnel/id_ed25519
exec ssh -NT \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/secrets/known_hosts \
  -o ExitOnForwardFailure=yes -o ConnectTimeout=15 \
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -i /run/tunnel/id_ed25519 -p "$VPN_SSH_PORT" -l "$VPN_SSH_USER" \
  -L 127.0.0.1:18787:127.0.0.1:8787 -- "$VPN_SSH_HOST"
