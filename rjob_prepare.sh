#!/usr/bin/env bash

RJOB_DOCKERD_PID=""
RJOB_DAEMON_CONFIG_BACKED_UP=0
RJOB_DAEMON_CONFIG="${CYBERGYM_DAEMON_CONFIG:-/etc/docker/daemon.json}"
RJOB_DAEMON_BACKUP="${CYBERGYM_DAEMON_BACKUP:-/tmp/safactory-docker-daemon.json.bak}"

prepare_rjob_docker() {
  local docker_log="${CYBERGYM_DOCKER_LOG:-/tmp/safactory-cybergym-dockerd.log}"
  local docker_root="${CYBERGYM_DOCKER_ROOT:-/docker-data}"

  command -v fuse-overlayfs >/dev/null 2>&1 || {
    cybergym_log "CyberGym DinD requires image-baked fuse-overlayfs"
    return 1
  }

  mkdir -p /var/run "$docker_root"
  rm -f /var/run/docker.sock

  if [[ -f "$RJOB_DAEMON_CONFIG" ]]; then
    cp "$RJOB_DAEMON_CONFIG" "$RJOB_DAEMON_BACKUP"
    RJOB_DAEMON_CONFIG_BACKED_UP=1
    python3.12 - "$RJOB_DAEMON_CONFIG" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
config = json.loads(path.read_text(encoding="utf-8"))
config.pop("data-root", None)
path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
PY
  fi

  dockerd \
    --storage-driver=fuse-overlayfs \
    --data-root="$docker_root" \
    >"$docker_log" 2>&1 &
  RJOB_DOCKERD_PID=$!
  export DOCKER_HOST="unix:///var/run/docker.sock"

  local attempt=0
  while (( attempt < 120 )); do
    if docker info >/dev/null 2>&1; then
      break
    fi
    if ! kill -0 "$RJOB_DOCKERD_PID" >/dev/null 2>&1; then
      cybergym_log "CyberGym DinD daemon exited during startup"
      tail -n 200 "$docker_log" >&2 || true
      return 1
    fi
    attempt=$((attempt + 1))
    sleep 1
  done

  if ! docker info >/dev/null 2>&1; then
    cybergym_log "CyberGym DinD daemon was not ready after 120 seconds"
    tail -n 200 "$docker_log" >&2 || true
    return 1
  fi

  local storage_driver
  storage_driver="$(docker info --format '{{.Driver}}')"
  if [[ "$storage_driver" != "fuse-overlayfs" ]]; then
    cybergym_log "CyberGym DinD started with unexpected storage driver: ${storage_driver}"
    return 1
  fi
}

cleanup_rjob_docker() {
  terminate_process "${RJOB_DOCKERD_PID:-}"
  if [[ "${RJOB_DAEMON_CONFIG_BACKED_UP:-0}" == "1" ]]; then
    cp "$RJOB_DAEMON_BACKUP" "$RJOB_DAEMON_CONFIG" || true
    rm -f "$RJOB_DAEMON_BACKUP"
    RJOB_DAEMON_CONFIG_BACKED_UP=0
  fi
}
