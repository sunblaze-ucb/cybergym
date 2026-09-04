#!/usr/bin/env bash

docker_image_exists() {
  "$EPISODE_DOCKER_BIN" image inspect "$1" >/dev/null 2>&1
}

docker_archive_name() {
  printf '%s.tar\n' "$1" | sed 's#[/:]#__#g'
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
  if [[ -n "${CYBERGYM_DEBUG_DIR:-}" ]]; then
    actions_dir="${CYBERGYM_DEBUG_DIR}/image-actions"
    mkdir -p "$actions_dir"
  else
    actions_dir="$(mktemp -d "${CYBERGYM_RUNNER_TMP}/image-actions.XXXXXX")"
  fi

  local index=0 image archive action_path load_output load_rc
  while IFS='|' read -r image archive; do
    [[ -n "$image" ]] || continue
    if docker_image_exists "$image"; then
      cybergym_log "Docker image already available: ${image}"
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
    cybergym_log "Loading Docker image ${image} from ${archive}"
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
    cybergym_log "Docker image ready: ${image}"
  done <<EOF
${EPISODE_AGENT_IMAGE}|${agent_archive}
${vul_image}|${vul_archive}
${fix_image}|${fix_archive}
EOF

  local inspect_path="${CYBERGYM_RUNNER_TMP}/controller-inspect.json"
  local bridge_path="${CYBERGYM_RUNNER_TMP}/bridge-inspect.json"
  local network_debug_path="${CYBERGYM_RUNNER_TMP}/docker-network-debug.json"
  if [[ -n "${CYBERGYM_DEBUG_DIR:-}" ]]; then
    inspect_path="${CYBERGYM_DEBUG_DIR}/controller-inspect.json"
    bridge_path="${CYBERGYM_DEBUG_DIR}/bridge-inspect.json"
    network_debug_path="${CYBERGYM_DEBUG_DIR}/docker-network-debug.json"
  fi
  "$EPISODE_DOCKER_BIN" inspect "$(hostname)" >"$inspect_path" 2>/dev/null || printf '[]\n' >"$inspect_path"
  "$EPISODE_DOCKER_BIN" network inspect bridge >"$bridge_path" 2>/dev/null || printf '[]\n' >"$bridge_path"

  local detected_env="${CYBERGYM_RUNNER_TMP}/docker-network.env"
  python3.12 - \
    "$inspect_path" \
    "$bridge_path" \
    "$EPISODE_CONFIGURED_RUNTIME_HOST" \
    "$EPISODE_CONFIGURED_CONTROLLER_HOST" \
    "$detected_env" \
    "$network_debug_path" <<'PY'
import ipaddress
import json
import shlex
import socket
import sys
from pathlib import Path

(
    inspect_path,
    bridge_path,
    configured_runtime_host,
    configured_controller_host,
    env_path,
    debug_path,
) = sys.argv[1:]
inspect = json.loads(Path(inspect_path).read_text(encoding="utf-8"))
bridge = json.loads(Path(bridge_path).read_text(encoding="utf-8"))
container_ip = ""
container_gateway = ""
bridge_gateway = ""
bridge_subnet = ""
if isinstance(inspect, list) and inspect:
    networks = ((inspect[0].get("NetworkSettings") or {}).get("Networks") or {})
    ordered = [networks.get("bridge")]
    ordered.extend(networks[name] for name in sorted(networks) if name != "bridge")
    for network in ordered:
        if not isinstance(network, dict):
            continue
        container_ip = container_ip or str(network.get("IPAddress") or "").strip()
        container_gateway = container_gateway or str(network.get("Gateway") or "").strip()
        if container_ip and container_gateway:
            break
if isinstance(bridge, list) and bridge:
    configs = ((bridge[0].get("IPAM") or {}).get("Config") or [])
    for config in configs:
        if not isinstance(config, dict):
            continue
        bridge_gateway = bridge_gateway or str(config.get("Gateway") or "").strip()
        bridge_subnet = bridge_subnet or str(config.get("Subnet") or "").strip()
        if bridge_gateway and bridge_subnet:
            break

# A newly-created DinD bridge may expose its subnet before Docker materializes
# the Gateway field. Docker uses the first usable address for the bridge in
# this case (for example 172.17.0.0/16 -> 172.17.0.1).
inferred_gateway = ""
subnet_error = ""
if not bridge_gateway and bridge_subnet:
    try:
        network = ipaddress.ip_network(bridge_subnet, strict=False)
        inferred_gateway = str(network.network_address + 1)
    except (ValueError, IndexError) as exc:
        subnet_error = str(exc)

socket_candidates = []
socket_errors = []
try:
    socket_candidates.extend(socket.gethostbyname_ex(socket.gethostname())[2])
except OSError as exc:
    socket_errors.append(f"hostname lookup: {exc}")
try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("192.0.2.1", 9))
        socket_candidates.append(sock.getsockname()[0])
except OSError as exc:
    socket_errors.append(f"UDP route probe: {exc}")
socket_candidates = list(dict.fromkeys(
    value.strip() for value in socket_candidates
    if value and not value.startswith("127.") and value != "0.0.0.0"
))

gateway_candidates = [
    ("container_inspect", container_gateway),
    ("bridge_ipam", bridge_gateway),
    ("bridge_subnet_inferred", inferred_gateway),
]
gateway_source, gateway = next(
    ((source, value) for source, value in gateway_candidates if value),
    ("", ""),
)
runtime_host = configured_runtime_host.strip() or gateway
runtime_source = "configured" if configured_runtime_host.strip() else gateway_source

# With DinD the controller Pod is not listed by the inner Docker daemon. The
# Docker bridge gateway belongs to the controller network namespace and is the
# most reliable address for a child agent container to call back to the server.
if configured_controller_host.strip():
    controller_host = configured_controller_host.strip()
    controller_source = "configured"
elif container_ip:
    controller_host = container_ip
    controller_source = "controller_inspect"
elif gateway:
    controller_host = gateway
    controller_source = gateway_source
elif socket_candidates:
    controller_host = socket_candidates[0]
    controller_source = "controller_socket"
else:
    controller_host = ""
    controller_source = ""

Path(env_path).write_text(
    f"DETECTED_RUNTIME_HOST={shlex.quote(runtime_host)}\n"
    f"DETECTED_CONTROLLER_HOST={shlex.quote(controller_host)}\n",
    encoding="utf-8",
)
Path(debug_path).write_text(
    json.dumps(
        {
            "configured": {
                "runtime_host": configured_runtime_host,
                "controller_host": configured_controller_host,
            },
            "controller_inspect": {
                "container_ip": container_ip,
                "gateway": container_gateway,
                "objects": len(inspect) if isinstance(inspect, list) else None,
            },
            "bridge": {
                "gateway": bridge_gateway,
                "subnet": bridge_subnet,
                "inferred_gateway": inferred_gateway,
                "subnet_error": subnet_error,
            },
            "controller_socket_candidates": socket_candidates,
            "controller_socket_errors": socket_errors,
            "selected": {
                "runtime_host": runtime_host,
                "runtime_source": runtime_source,
                "controller_host": controller_host,
                "controller_source": controller_source,
            },
        },
        ensure_ascii=False,
        indent=2,
    ) + "\n",
    encoding="utf-8",
)
PY
  # shellcheck disable=SC1090
  source "$detected_env"

  if [[ -z "$DETECTED_RUNTIME_HOST" ]]; then
    cybergym_log "Could not determine the Docker gateway; see ${network_debug_path}"
    return 1
  fi
  if [[ -z "$DETECTED_CONTROLLER_HOST" ]]; then
    cybergym_log "Could not determine an address reachable by the agent container; see ${network_debug_path}"
    return 1
  fi
  cybergym_log "Docker networking: runtime_host=${DETECTED_RUNTIME_HOST} controller_host=${DETECTED_CONTROLLER_HOST} debug=${network_debug_path}"

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
