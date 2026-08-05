#!/usr/bin/env bash

cybergym_log() {
  printf '[safactory-cybergym] %s\n' "$*" >&2
}

phase_timeout() {
  local configured_timeout="$1"
  local reserve_s="$2"
  local minimum_s="$3"
  local now remaining
  now="$(date +%s)"
  remaining=$((EPISODE_DEADLINE_EPOCH - now - reserve_s))
  if (( remaining < minimum_s )); then
    cybergym_log "insufficient episode budget: remaining=${remaining}s minimum=${minimum_s}s"
    return 1
  fi
  if (( configured_timeout < remaining )); then
    printf '%s\n' "$configured_timeout"
  else
    printf '%s\n' "$remaining"
  fi
}

wait_for_cybergym_server() {
  local url="$1"
  local pid="$2"
  local timeout_s="$3"
  local deadline=$(( $(date +%s) + timeout_s ))
  local last_error=""
  while (( $(date +%s) < deadline )); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      cybergym_log "CyberGym server exited during startup"
      return 1
    fi
    if last_error="$(curl -fsS --max-time 2 "${url}/openapi.json" 2>&1 >/dev/null)"; then
      return 0
    fi
    sleep 0.25
  done
  cybergym_log "CyberGym server did not become ready: ${last_error}"
  return 1
}

terminate_process() {
  local pid="${1:-}"
  if [[ -z "$pid" ]] || ! kill -0 "$pid" >/dev/null 2>&1; then
    return 0
  fi
  kill "$pid" >/dev/null 2>&1 || true
  local attempt=0
  while (( attempt < 20 )); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      wait "$pid" >/dev/null 2>&1 || true
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.25
  done
  kill -9 "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}
