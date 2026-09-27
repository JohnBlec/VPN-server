#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $# -lt 1 || $# -gt 2 ]]; then
  printf 'Usage: bash scripts/backup.sh age1RECIPIENT [output-directory]\n' >&2
  exit 2
fi
command -v age >/dev/null || { printf 'Install age first: sudo apt install age\n' >&2; exit 1; }
recipient=$1
output=${2:-./backups}
mkdir -p -- "$output"
output=$(cd -- "$output" && pwd)
name="aegis-vpn-$(date -u +%Y%m%dT%H%M%SZ)-$$.tar.gz.age"
container=$(docker compose ps -aq vpn)
[[ -n "$container" ]] || { printf 'Create the VPN container before backing up.\n' >&2; exit 1; }
running=$(docker inspect -f '{{.State.Running}}' "$container")
image=$(docker inspect -f '{{.Image}}' "$container")
metadata=$(mktemp -d)
cleanup() {
  status=$?
  if [[ "$running" == true ]]; then
    if ! docker compose start vpn >/dev/null; then
      printf 'WARNING: restart failed; run docker compose start vpn\n' >&2
      status=1
    fi
  fi
  # Only our two files and empty temporary directory; no recursive deletion.
  rm -f -- "$metadata/image.txt"
  rmdir -- "$metadata"
  exit "$status"
}
trap cleanup EXIT
docker image inspect "$image" --format '{{.Id}} {{json .RepoTags}}' > "$metadata/image.txt"
if [[ "$running" == true ]]; then
  docker compose stop vpn
fi
tar -czf - .env secrets data compose.yml Dockerfile .dockerignore agent.py entrypoint.py traffic.py -C "$metadata" image.txt \
  | age --recipient "$recipient" --output "$output/$name.partial"
mv -- "$output/$name.partial" "$output/$name"
printf 'Encrypted backup: %s\n' "$output/$name"
printf 'Copy it off this VPS. Keep the age identity separately.\n'
