#!/usr/bin/env bash

docker_image_exists() {
  "$EPISODE_DOCKER_BIN" image inspect "$1" >/dev/null 2>&1
}

docker_archive_name() {
  printf '%s.tar\n' "$1" | sed 's#[/:]#__#g'
}

controller_reachable_host() {
  python3.12 - <<'PY'
import socket

candidates = []
try:
    candidates.extend(socket.gethostbyname_ex(socket.gethostname())[2])
except OSError:
    pass
try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("192.0.2.1", 9))
        candidates.append(sock.getsockname()[0])
except OSError:
    pass
for value in candidates:
    if value and not value.startswith("127.") and value != "0.0.0.0":
        print(value)
        raise SystemExit(0)
raise SystemExit(1)
PY
}

prepare_docker_assets() {
  local output_json="$1"
  local output_env="$2"
  local image_timeout_s="$3"
  local task_subset="${EPISODE_TASK_ID%%:*}"
  local task_subid="${EPISODE_TASK_ID#*:}"
  if [[ "$task_subset" == "$EPISODE_TASK_ID" || -z "$task_subid" ]]; then
    cybergym_log "Invalid CyberGym task_id: ${EPISODE_TASK_ID}"
    return 1
  fi

  local vul_image fix_image
  case "$task_subset" in
    arvo)
      vul_image="n132/arvo:${task_subid}-vul"
      fix_image="n132/arvo:${task_subid}-fix"
      ;;
    oss-fuzz)
      vul_image="cybergym/oss-fuzz:${task_subid}-vul"
      fix_image="cybergym/oss-fuzz:${task_subid}-fix"
      ;;
    oss-fuzz-latest)
      cybergym_log "oss-fuzz-latest does not provide a fixed image for final-submission evaluation"
      return 1
      ;;
    *)
      cybergym_log "Unsupported CyberGym task type: ${task_subset}"
      return 1
      ;;
  esac

  if ! "$EPISODE_DOCKER_BIN" info >/dev/null 2>&1; then
    cybergym_log "Docker daemon is unavailable through ${DOCKER_HOST:-the default socket}"
    return 1
  fi

  local agent_archive="$EPISODE_AGENT_IMAGE_ARCHIVE"
  if [[ "$agent_archive" != /* ]]; then
    agent_archive="${EPISODE_IMAGE_ARCHIVE_DIR}/${agent_archive}"
  fi
  local vul_archive="${EPISODE_IMAGE_ARCHIVE_DIR}/$(docker_archive_name "$vul_image")"
  local fix_archive="${EPISODE_IMAGE_ARCHIVE_DIR}/$(docker_archive_name "$fix_image")"
  local actions_dir
  actions_dir="$(mktemp -d "${CYBERGYM_RUNNER_TMP}/image-actions.XXXXXX")"

  local index=0 image archive action_path load_output load_rc
  while IFS='|' read -r image archive; do
    [[ -n "$image" ]] || continue
    if docker_image_exists "$image"; then
      continue
    fi
    if [[ ! -f "$archive" ]]; then
      cybergym_log "Docker image archive does not exist for ${image}: ${archive}"
      return 1
    fi
    case "${archive,,}" in
      *.tar|*.tar.gz|*.tgz) ;;
      *)
        cybergym_log "Unsupported Docker image archive for ${image}: ${archive}"
        return 1
        ;;
    esac

    index=$((index + 1))
    action_path="${actions_dir}/$(printf '%04d' "$index").json"
    load_output="${actions_dir}/$(printf '%04d' "$index").log"
    set +e
    timeout --signal=TERM --kill-after=30 "${image_timeout_s}s" \
      "$EPISODE_DOCKER_BIN" load --input "$archive" >"$load_output" 2>&1
    load_rc=$?
    set -e
    python3.12 - "$action_path" "$image" "$archive" "$load_rc" "$load_output" <<'PY'
import json
import sys
from pathlib import Path

output, image, archive, returncode, log_path = sys.argv[1:]
text = Path(log_path).read_text(encoding="utf-8", errors="replace")
Path(output).write_text(
    json.dumps(
        {
            "action": "load",
            "image": image,
            "archive": archive,
            "returncode": int(returncode),
            "output_tail": text[-2000:],
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)
PY
    if (( load_rc != 0 )); then
      cybergym_log "Could not load Docker image ${image} from ${archive}"
      tail -n 50 "$load_output" >&2 || true
      return 1
    fi
    if ! docker_image_exists "$image"; then
      cybergym_log "Docker archive ${archive} did not provide expected tag ${image}"
      return 1
    fi
  done <<EOF
${EPISODE_AGENT_IMAGE}|${agent_archive}
${vul_image}|${vul_archive}
${fix_image}|${fix_archive}
EOF

  local inspect_path="${CYBERGYM_RUNNER_TMP}/controller-inspect.json"
  local bridge_path="${CYBERGYM_RUNNER_TMP}/bridge-inspect.json"
  "$EPISODE_DOCKER_BIN" inspect "$(hostname)" >"$inspect_path" 2>/dev/null || printf '[]\n' >"$inspect_path"
  "$EPISODE_DOCKER_BIN" network inspect bridge >"$bridge_path" 2>/dev/null || printf '[]\n' >"$bridge_path"

  local detected_env="${CYBERGYM_RUNNER_TMP}/docker-network.env"
  python3.12 - \
    "$inspect_path" \
    "$bridge_path" \
    "$EPISODE_CONFIGURED_RUNTIME_HOST" \
    "$EPISODE_CONFIGURED_CONTROLLER_HOST" \
    "$detected_env" <<'PY'
import json
import shlex
import sys
from pathlib import Path

inspect_path, bridge_path, runtime_host, controller_host, env_path = sys.argv[1:]
inspect = json.loads(Path(inspect_path).read_text(encoding="utf-8"))
bridge = json.loads(Path(bridge_path).read_text(encoding="utf-8"))
container_ip = ""
gateway = ""
if isinstance(inspect, list) and inspect:
    networks = ((inspect[0].get("NetworkSettings") or {}).get("Networks") or {})
    ordered = [networks.get("bridge")]
    ordered.extend(networks[name] for name in sorted(networks) if name != "bridge")
    for network in ordered:
        if not isinstance(network, dict):
            continue
        container_ip = container_ip or str(network.get("IPAddress") or "").strip()
        gateway = gateway or str(network.get("Gateway") or "").strip()
        if container_ip and gateway:
            break
if not gateway and isinstance(bridge, list) and bridge:
    configs = ((bridge[0].get("IPAM") or {}).get("Config") or [])
    for config in configs:
        if isinstance(config, dict) and config.get("Gateway"):
            gateway = str(config["Gateway"]).strip()
            break
runtime_host = runtime_host.strip() or gateway
controller_host = controller_host.strip() or container_ip
Path(env_path).write_text(
    f"DETECTED_RUNTIME_HOST={shlex.quote(runtime_host)}\n"
    f"DETECTED_CONTROLLER_HOST={shlex.quote(controller_host)}\n",
    encoding="utf-8",
)
PY
  # shellcheck disable=SC1090
  source "$detected_env"

  if [[ -z "$DETECTED_RUNTIME_HOST" ]]; then
    cybergym_log "Could not determine the Docker gateway used to reach the OpenHands runtime"
    return 1
  fi
  if [[ -z "$DETECTED_CONTROLLER_HOST" ]]; then
    DETECTED_CONTROLLER_HOST="$(controller_reachable_host)" || {
      cybergym_log "Could not determine an address reachable by the OpenHands runtime"
      return 1
    }
  fi

  local agent_server_url url_host="$DETECTED_CONTROLLER_HOST"
  if [[ "$url_host" == *"://"* ]]; then
    agent_server_url="${url_host%/}:${EPISODE_SERVER_PORT}"
  else
    if [[ "$url_host" == *:* && "$url_host" != \[*\] ]]; then
      url_host="[${url_host}]"
    fi
    agent_server_url="http://${url_host}:${EPISODE_SERVER_PORT}"
  fi

  python3.12 - \
    "$output_json" \
    "$actions_dir" \
    "$EPISODE_AGENT_IMAGE" \
    "$vul_image" \
    "$fix_image" \
    "$DETECTED_RUNTIME_HOST" \
    "$DETECTED_CONTROLLER_HOST" \
    "$agent_server_url" <<'PY'
import json
import sys
from pathlib import Path

output, actions_dir, agent, vul, fix, runtime_host, controller_host, server_url = sys.argv[1:]
actions = [
    json.loads(path.read_text(encoding="utf-8"))
    for path in sorted(Path(actions_dir).glob("*.json"))
]
Path(output).write_text(
    json.dumps(
        {
            "required_images": [agent, vul, fix],
            "image_loads": actions,
            "runtime_host": runtime_host,
            "controller_host": controller_host,
            "agent_server_url": server_url,
        },
        ensure_ascii=False,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY

  {
    printf 'EPISODE_RUNTIME_HOST=%q\n' "$DETECTED_RUNTIME_HOST"
    printf 'EPISODE_CONTROLLER_HOST=%q\n' "$DETECTED_CONTROLLER_HOST"
    printf 'EPISODE_AGENT_SERVER_URL=%q\n' "$agent_server_url"
  } >"$output_env"
}
