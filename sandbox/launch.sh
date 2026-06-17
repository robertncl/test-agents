#!/usr/bin/env bash
#
# launch.sh — build/run the sandbox target the Group 2 test agents probe.
#
# The hardened profile applies the OS-level restrictions the POC plan expects of a
# local sandbox; the SC-07/SC-08/SC-11 agents then verify, from inside the running
# container, that out-of-bounds actions are blocked.
#
#   ./launch.sh up                 # build + run hardened target  (expect SC-07/11 PASS)
#   ./launch.sh up --insecure      # run WITHOUT restrictions      (expect SC-07/11 FAIL — contrast)
#   ./launch.sh up-pair            # run session-a/-b for SC-09 docker volume check
#   ./launch.sh status | shell | down
#
# Hardening applied (hardened profile):
#   --network none              default-deny egress (nothing allowlisted -> all blocked)
#   --read-only                 immutable rootfs (writes confined to tmpfs /workspace,/tmp)
#   --cap-drop ALL              no Linux capabilities (blocks mount/raw-net/etc.)
#   --security-opt no-new-privileges  no setuid/su privilege gain
#   --pids-limit / --memory     basic resource bounds
#   runs as non-root uid 1000 (from the image)
set -euo pipefail

IMAGE="copilot-sandbox:poc"
NAME="${SANDBOX_NAME:-copilot-sandbox}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HARDENED_FLAGS=(
  --network none
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit 128
  --memory 512m
  --tmpfs /workspace:rw,nosuid,nodev,size=64m,mode=1777
  --tmpfs /tmp:rw,nosuid,nodev,size=16m
)

INSECURE_FLAGS=(
  # Deliberately permissive: a useful negative control to show probes catch bypasses.
  --cap-add ALL
)

build() {
  docker build -t "$IMAGE" "$HERE"
}

up() {
  local insecure=0
  [[ "${1:-}" == "--insecure" ]] && insecure=1
  build
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [[ $insecure -eq 1 ]]; then
    echo ">> launching INSECURE target '$NAME' (negative control)"
    docker run -d --name "$NAME" "${INSECURE_FLAGS[@]}" "$IMAGE" >/dev/null
  else
    echo ">> launching HARDENED target '$NAME'"
    docker run -d --name "$NAME" "${HARDENED_FLAGS[@]}" "$IMAGE" >/dev/null
  fi
  docker ps --filter "name=^/${NAME}$" --format '   running: {{.Names}} ({{.Status}})'
}

up_pair() {
  build
  for s in a b; do
    docker rm -f "${NAME}-${s}" >/dev/null 2>&1 || true
    docker run -d --name "${NAME}-${s}" "${HARDENED_FLAGS[@]}" "$IMAGE" >/dev/null
    docker exec "${NAME}-${s}" bash -lc "echo session-${s}-secret > /workspace/session_${s}.txt"
  done
  echo ">> launched ${NAME}-a and ${NAME}-b (separate volumes) for SC-09"
}

case "${1:-}" in
  up)       shift; up "${1:-}";;
  up-pair)  up_pair;;
  down)     docker rm -f "$NAME" "${NAME}-a" "${NAME}-b" >/dev/null 2>&1 || true; echo ">> removed";;
  status)   docker ps --filter "name=${NAME}" --format '{{.Names}}\t{{.Status}}';;
  shell)    docker exec -it "$NAME" bash;;
  build)    build;;
  *) echo "usage: $0 {up [--insecure]|up-pair|down|status|shell|build}"; exit 2;;
esac
