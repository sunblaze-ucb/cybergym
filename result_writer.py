#!/usr/bin/env python3
"""Discover CyberGym artifacts and emit the Safactory episode protocol result."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import time
from pathlib import Path
from typing import Any


RESULT_JSON_PREFIX = "SAFACTORY_RESULT_JSON "


def discover_openhands_result(log_dir: Path, task_id: str) -> dict[str, Any]:
    candidates: list[tuple[int, Path, dict[str, Any]]] = []
    for args_path in log_dir.rglob("args.json"):
        try:
            payload = json.loads(args_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                continue
            task = payload.get("task") if isinstance(payload.get("task"), dict) else {}
            payload_task_id = first_text(task.get("task_id"))
            if payload_task_id and payload_task_id != task_id:
                continue
            candidates.append((args_path.stat().st_mtime_ns, args_path, payload))
        except (OSError, json.JSONDecodeError):
            continue
    if not candidates:
        return {
            "agent_id": None,
            "args_path": None,
            "trajectory_path": None,
            "step_count": 0,
            "agent": None,
        }

    _mtime, args_path, payload = max(candidates, key=lambda item: item[0])
    task = payload.get("task") if isinstance(payload.get("task"), dict) else {}
    trajectory_path = args_path.parent / "trajectory"
    return {
        "agent_id": first_text(task.get("agent_id")) or None,
        "args_path": str(args_path),
        "trajectory_path": str(trajectory_path) if trajectory_path.is_file() else None,
        "step_count": trajectory_step_count(trajectory_path),
        "agent": payload.get("agent"),
    }


def trajectory_step_count(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return 0
    if not text:
        return 0
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return sum(1 for line in text.splitlines() if line.strip())
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("events", "steps", "trajectory"):
            items = value.get(key)
            if isinstance(items, list):
                return len(items)
    return 1


def rollout_status(
    *,
    native_returncode: int,
    native_output_tail: str,
    native_result: dict[str, Any],
    verification_error: str,
) -> tuple[str, str | None]:
    if not first_text(native_result.get("agent_id")):
        return "failed", "OpenHands did not produce an args.json with a CyberGym agent_id"
    if verification_error:
        return "failed", f"CyberGym verification failed: {verification_error}"
    if native_returncode != 0:
        detail = tail(native_output_tail, 1000).strip()
        return "failed", f"OpenHands exited with code {native_returncode}: {detail}"
    if not native_result.get("trajectory_path"):
        return "failed", "OpenHands did not produce a trajectory"
    return "succeeded", None


def write_final(
    *,
    episode_path: Path,
    docker_path: Path,
    native_path: Path,
    native_returncode: int,
    native_output_path: Path,
    verification_returncode: int | None,
    verification_error: str,
    verification_output_path: Path,
) -> dict[str, Any]:
    episode = read_mapping(episode_path)
    docker = read_mapping(docker_path)
    native_result = read_mapping(native_path)
    native_output_tail = read_tail(native_output_path, 5000)
    verification_output_tail = read_tail(verification_output_path, 5000)
    agent_id = first_text(native_result.get("agent_id"))
    status, error_text = rollout_status(
        native_returncode=native_returncode,
        native_output_tail=native_output_tail,
        native_result=native_result,
        verification_error=verification_error,
    )
    result = {
        "session_id": episode.get("session_id", ""),
        "status": status,
        "total_reward": 0.0,
        "step_count": max(1, int_value(native_result.get("step_count"), 1)),
        "terminated": True,
        "truncated": native_returncode == 124
        or "timed out" in native_output_tail.lower(),
        "error_text": error_text,
        "metrics": {
            "bench": "cybergym",
            "task_id": episode.get("task_id"),
            "difficulty": episode.get("difficulty"),
            "model_ref": episode.get("model_ref"),
            "max_iter": episode.get("max_iter"),
            "cybergym_agent_id": agent_id or None,
            "native_returncode": native_returncode,
            "native_output_tail": native_output_tail,
            "native_result": native_result,
            "trajectory_path": native_result.get("trajectory_path"),
            "verification_error": verification_error or None,
            "verification_returncode": verification_returncode,
            "verification_output_tail": verification_output_tail,
            "required_images": docker.get("required_images", []),
            "image_loads": docker.get("image_loads", []),
            "image_archive_dir": episode.get("image_archive_dir"),
            "results_dir": episode.get("results_dir"),
            "agent_server_url": docker.get("agent_server_url"),
            "controller_host": docker.get("controller_host"),
            "openhands_runtime_host": docker.get("runtime_host"),
            "gateway_url": episode.get("gateway_url"),
            "db_path": episode.get("db_path"),
            "duration_ms": duration_ms(episode),
        },
    }
    persist_and_emit(result, Path(str(episode["results_dir"])))
    return result


def write_failure(
    *,
    reason: str,
    request_path: Path | None,
    episode_path: Path | None,
    truncated: bool,
) -> dict[str, Any]:
    request = read_mapping(request_path) if request_path and request_path.is_file() else {}
    episode = read_mapping(episode_path) if episode_path and episode_path.is_file() else {}
    session_id = first_text(
        episode.get("session_id"),
        request.get("session_id"),
        os.environ.get("SAFACTORY_SESSION_ID"),
    )
    result = {
        "session_id": session_id,
        "status": "failed",
        "total_reward": 0.0,
        "step_count": 0,
        "terminated": True,
        "truncated": truncated,
        "error_text": reason,
        "metrics": {
            "bench": "cybergym",
            "task_id": episode.get("task_id"),
            "results_dir": episode.get("results_dir"),
            "db_path": episode.get("db_path"),
            "duration_ms": duration_ms(episode),
        },
    }
    results_dir = first_text(episode.get("results_dir"))
    persist_and_emit(result, Path(results_dir) if results_dir else None)
    return result


def persist_and_emit(result: dict[str, Any], results_dir: Path | None) -> None:
    if results_dir is not None:
        write_json_atomic(results_dir / "safactory_result.json", result)
    print(
        RESULT_JSON_PREFIX
        + json.dumps(result, ensure_ascii=False, default=str),
        flush=True,
    )


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    tmp_path.replace(path)


def write_discovery(log_dir: Path, task_id: str, output: Path, env_out: Path) -> None:
    result = discover_openhands_result(log_dir, task_id)
    write_json_atomic(output, result)
    mapping = {
        "EPISODE_AGENT_ID": first_text(result.get("agent_id")),
        "EPISODE_TRAJECTORY_PATH": first_text(result.get("trajectory_path")),
        "EPISODE_STEP_COUNT": int_value(result.get("step_count")),
    }
    env_out.parent.mkdir(parents=True, exist_ok=True)
    env_out.write_text(
        "".join(f"{key}={shlex.quote(str(value))}\n" for key, value in mapping.items()),
        encoding="utf-8",
    )


def read_mapping(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


def read_tail(path: Path, limit: int) -> str:
    try:
        return tail(path.read_text(encoding="utf-8"), limit)
    except OSError:
        return ""


def duration_ms(episode: dict[str, Any]) -> float:
    try:
        started = float(episode.get("started_at_epoch") or time.time())
    except (TypeError, ValueError):
        started = time.time()
    return round(max(0.0, time.time() - started) * 1000, 3)


def first_text(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def int_value(*values: Any) -> int:
    for value in values:
        if value is None or str(value).strip() == "":
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def tail(value: str, limit: int) -> str:
    return (value or "")[-limit:]


def optional_int(value: str) -> int | None:
    text = str(value or "").strip()
    return int(text) if text else None


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover")
    discover.add_argument("--log-dir", type=Path, required=True)
    discover.add_argument("--task-id", required=True)
    discover.add_argument("--output", type=Path, required=True)
    discover.add_argument("--env-out", type=Path, required=True)

    final = subparsers.add_parser("final")
    final.add_argument("--episode", type=Path, required=True)
    final.add_argument("--docker", type=Path, required=True)
    final.add_argument("--native", type=Path, required=True)
    final.add_argument("--native-returncode", type=int, required=True)
    final.add_argument("--native-output", type=Path, required=True)
    final.add_argument("--verification-returncode", default="")
    final.add_argument("--verification-error", default="")
    final.add_argument("--verification-output", type=Path, required=True)

    failure = subparsers.add_parser("failure")
    failure.add_argument("--reason", required=True)
    failure.add_argument("--request", type=Path)
    failure.add_argument("--episode", type=Path)
    failure.add_argument("--truncated", action="store_true")

    args = parser.parse_args()
    if args.command == "discover":
        write_discovery(args.log_dir, args.task_id, args.output, args.env_out)
    elif args.command == "final":
        write_final(
            episode_path=args.episode,
            docker_path=args.docker,
            native_path=args.native,
            native_returncode=args.native_returncode,
            native_output_path=args.native_output,
            verification_returncode=optional_int(args.verification_returncode),
            verification_error=args.verification_error,
            verification_output_path=args.verification_output,
        )
    else:
        write_failure(
            reason=args.reason,
            request_path=args.request,
            episode_path=args.episode,
            truncated=args.truncated,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
