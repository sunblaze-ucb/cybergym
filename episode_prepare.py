#!/usr/bin/env python3
"""Resolve one Safactory request into stable CyberGym episode settings."""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import socket
import time
from pathlib import Path
from typing import Any


def configured_path(
    dataset: dict[str, Any],
    env_params: dict[str, Any],
    key: str,
    env_key: str,
) -> Path:
    value = first_text(dataset.get(key), env_params.get(key), os.environ.get(env_key))
    if not value:
        raise RuntimeError(
            f"Missing required CyberGym path setting: {key} "
            f"(set env_params.{key} or {env_key})"
        )
    return Path(value).expanduser()


def results_dir(
    request: dict[str, Any],
    env_params: dict[str, Any],
    dataset: dict[str, Any],
) -> Path:
    root = configured_path(dataset, env_params, "results_root", "CYBERGYM_RESULTS_ROOT")
    return root / safe_part(request.get("job_id")) / safe_part(request.get("session_id"))


def model_ref(
    request: dict[str, Any],
    env_params: dict[str, Any],
    dataset: dict[str, Any],
) -> str:
    explicit = first_text(
        dataset.get("model_ref"),
        env_params.get("model_ref"),
        os.environ.get("CYBERGYM_MODEL_REF"),
    )
    value = explicit or first_text(
        dataset.get("route_model"),
        env_params.get("route_model"),
        os.environ.get("SAFACTORY_ROUTE_MODEL"),
        request.get("model"),
    )
    if not value:
        raise RuntimeError("CyberGym runner could not resolve an OpenHands model")
    if value.startswith("safactory/"):
        value = value.split("/", 1)[1]
    return value if "/" in value else f"openai/{value}"


def max_iter(
    request: dict[str, Any],
    env_params: dict[str, Any],
    dataset: dict[str, Any],
) -> int:
    configured = positive_int(
        dataset.get("max_iter"),
        env_params.get("max_iter"),
        default=positive_int(request.get("max_steps"), default=50),
    )
    request_limit = positive_int(request.get("max_steps"), default=configured)
    return max(1, min(configured, request_limit))


def prepare(request_path: Path, output_path: Path, env_path: Path) -> None:
    request = json.loads(request_path.read_text(encoding="utf-8"))
    if not isinstance(request, dict):
        raise RuntimeError("SimulationStartRequest must be a JSON object")

    session_id = required_text(request.get("session_id"), "session_id")
    env_params = request.get("env_params") if isinstance(request.get("env_params"), dict) else {}
    dataset = env_params.get("dataset") if isinstance(env_params.get("dataset"), dict) else {}
    task_id = required_text(dataset.get("task_id"), "env_params.dataset.task_id")
    difficulty = first_text(dataset.get("difficulty"), env_params.get("difficulty"), "level1")

    cybergym_root = configured_path(dataset, env_params, "cybergym_root", "CYBERGYM_ROOT")
    data_dir = configured_path(dataset, env_params, "data_dir", "CYBERGYM_DATA_DIR")
    image_archive_dir = configured_path(
        dataset,
        env_params,
        "image_archive_dir",
        "CYBERGYM_IMAGE_ARCHIVE_DIR",
    )
    openhands_runner = configured_path(
        dataset,
        env_params,
        "openhands_runner",
        "CYBERGYM_OPENHANDS_RUNNER",
    )
    openhands_repo = configured_path(
        dataset,
        env_params,
        "openhands_repo",
        "CYBERGYM_OPENHANDS_REPO",
    )
    result_dir = results_dir(request, env_params, dataset)
    server_dir = result_dir / "server"
    logs_dir = result_dir / "logs"
    tmp_dir = result_dir / "tmp"
    for directory in (result_dir, server_dir, logs_dir, tmp_dir):
        directory.mkdir(parents=True, exist_ok=True)

    validate_runtime_paths(
        cybergym_root=cybergym_root,
        data_dir=data_dir,
        image_archive_dir=image_archive_dir,
        openhands_runner=openhands_runner,
        openhands_repo=openhands_repo,
    )

    gateway_url = first_text(os.environ.get("SAFACTORY_GATEWAY_SESSION_URL_CONTAINER"))
    if not gateway_url:
        base = required_text(request.get("gateway_base_url"), "gateway_base_url").rstrip("/")
        gateway_url = f"{base}/{session_id}"

    agent_image = required_text(env_params.get("agent_image"), "env_params.agent_image")
    agent_image_archive = required_text(
        env_params.get("agent_image_archive"),
        "env_params.agent_image_archive",
    )
    verify_timeout_s = positive_int(
        dataset.get("verify_timeout_s"),
        env_params.get("verify_timeout_s"),
        default=600,
    )
    agent_timeout_s = positive_int(
        dataset.get("timeout_s"),
        env_params.get("timeout_s"),
        default=1800,
    )
    outer_timeout_s = positive_int(request.get("agent_start_timeout_s"), default=3600)
    server_port = free_port()
    started_at_epoch = time.time()

    settings: dict[str, Any] = {
        "session_id": session_id,
        "job_id": first_text(request.get("job_id")),
        "task_id": task_id,
        "difficulty": difficulty,
        "cybergym_root": str(cybergym_root),
        "data_dir": str(data_dir),
        "image_archive_dir": str(image_archive_dir),
        "results_dir": str(result_dir),
        "server_dir": str(server_dir),
        "logs_dir": str(logs_dir),
        "tmp_dir": str(tmp_dir),
        "db_path": str(server_dir / "poc.db"),
        "openhands_runner": str(openhands_runner),
        "openhands_repo": str(openhands_repo),
        "agent_image": agent_image,
        "agent_image_archive": agent_image_archive,
        "model_ref": model_ref(request, env_params, dataset),
        "gateway_url": gateway_url.rstrip("/"),
        "gateway_api_key": first_text(
            os.environ.get("SAFACTORY_GATEWAY_API_KEY"),
            "safactory",
        ),
        "cybergym_api_key": first_text(
            dataset.get("cybergym_api_key"),
            env_params.get("cybergym_api_key"),
            os.environ.get("CYBERGYM_API_KEY"),
            secrets.token_urlsafe(32),
        ),
        "max_iter": max_iter(request, env_params, dataset),
        "temperature": first_text(
            dataset.get("temperature"),
            env_params.get("temperature"),
            request.get("temperature"),
            "0.0",
        ),
        "top_p": first_text(dataset.get("top_p"), env_params.get("top_p"), "1.0"),
        "max_output_tokens": first_text(
            dataset.get("max_output_tokens"),
            env_params.get("max_output_tokens"),
            "4096",
        ),
        "silent": bool_value(
            dataset.get("silent"),
            env_params.get("silent"),
            default=True,
        ),
        "native_tool_calling": optional_bool(
            dataset.get("native_tool_calling"),
            env_params.get("native_tool_calling"),
        ),
        "configured_agent_timeout_s": agent_timeout_s,
        "configured_verify_timeout_s": verify_timeout_s,
        "image_load_timeout_s": positive_int(
            dataset.get("image_load_timeout_s"),
            env_params.get("image_load_timeout_s"),
            default=1800,
        ),
        "deadline_epoch": int(started_at_epoch + outer_timeout_s),
        "started_at_epoch": started_at_epoch,
        "docker_bin": first_text(os.environ.get("DOCKER_BIN"), "docker"),
        "python_bin": first_text(os.environ.get("PYTHON_BIN"), "python3.12"),
        "configured_runtime_host": first_text(
            dataset.get("openhands_runtime_host"),
            env_params.get("openhands_runtime_host"),
            os.environ.get("CYBERGYM_OPENHANDS_RUNTIME_HOST"),
        ),
        "configured_controller_host": first_text(
            dataset.get("agent_server_host"),
            env_params.get("agent_server_host"),
            os.environ.get("CYBERGYM_AGENT_SERVER_HOST"),
        ),
        "server_port": server_port,
        "server_url": f"http://127.0.0.1:{server_port}",
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(settings, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_env(env_path, settings)


def validate_runtime_paths(
    *,
    cybergym_root: Path,
    data_dir: Path,
    image_archive_dir: Path,
    openhands_runner: Path,
    openhands_repo: Path,
) -> None:
    checks = (
        (cybergym_root.is_dir(), f"CyberGym root does not exist: {cybergym_root}"),
        (data_dir.is_dir(), f"CyberGym data directory does not exist: {data_dir}"),
        (
            image_archive_dir.is_dir(),
            f"CyberGym image archive directory does not exist: {image_archive_dir}",
        ),
        (
            openhands_runner.is_file(),
            f"OpenHands CyberGym runner does not exist: {openhands_runner}",
        ),
        (
            (openhands_runner.parent / "template" / "config.toml").is_file(),
            f"OpenHands CyberGym template does not exist next to {openhands_runner}",
        ),
        (openhands_repo.is_dir(), f"OpenHands repository does not exist: {openhands_repo}"),
        (
            (openhands_repo / "Makefile").is_file(),
            f"OpenHands repository is not populated or built: {openhands_repo}",
        ),
    )
    for valid, message in checks:
        if not valid:
            raise RuntimeError(message)


def write_env(path: Path, settings: dict[str, Any]) -> None:
    mapping = {
        "EPISODE_SESSION_ID": settings["session_id"],
        "EPISODE_TASK_ID": settings["task_id"],
        "EPISODE_DIFFICULTY": settings["difficulty"],
        "EPISODE_CYBERGYM_ROOT": settings["cybergym_root"],
        "EPISODE_DATA_DIR": settings["data_dir"],
        "EPISODE_IMAGE_ARCHIVE_DIR": settings["image_archive_dir"],
        "EPISODE_RESULTS_DIR": settings["results_dir"],
        "EPISODE_SERVER_DIR": settings["server_dir"],
        "EPISODE_LOGS_DIR": settings["logs_dir"],
        "EPISODE_TMP_DIR": settings["tmp_dir"],
        "EPISODE_DB_PATH": settings["db_path"],
        "EPISODE_OPENHANDS_RUNNER": settings["openhands_runner"],
        "EPISODE_OPENHANDS_REPO": settings["openhands_repo"],
        "EPISODE_AGENT_IMAGE": settings["agent_image"],
        "EPISODE_AGENT_IMAGE_ARCHIVE": settings["agent_image_archive"],
        "EPISODE_MODEL_REF": settings["model_ref"],
        "EPISODE_GATEWAY_URL": settings["gateway_url"],
        "EPISODE_GATEWAY_API_KEY": settings["gateway_api_key"],
        "EPISODE_CYBERGYM_API_KEY": settings["cybergym_api_key"],
        "EPISODE_MAX_ITER": settings["max_iter"],
        "EPISODE_TEMPERATURE": settings["temperature"],
        "EPISODE_TOP_P": settings["top_p"],
        "EPISODE_MAX_OUTPUT_TOKENS": settings["max_output_tokens"],
        "EPISODE_SILENT": str(settings["silent"]).lower(),
        "EPISODE_NATIVE_TOOL_CALLING": (
            ""
            if settings["native_tool_calling"] is None
            else str(settings["native_tool_calling"]).lower()
        ),
        "EPISODE_AGENT_TIMEOUT_S": settings["configured_agent_timeout_s"],
        "EPISODE_VERIFY_TIMEOUT_S": settings["configured_verify_timeout_s"],
        "EPISODE_IMAGE_LOAD_TIMEOUT_S": settings["image_load_timeout_s"],
        "EPISODE_DEADLINE_EPOCH": settings["deadline_epoch"],
        "EPISODE_DOCKER_BIN": settings["docker_bin"],
        "EPISODE_PYTHON_BIN": settings["python_bin"],
        "EPISODE_CONFIGURED_RUNTIME_HOST": settings["configured_runtime_host"],
        "EPISODE_CONFIGURED_CONTROLLER_HOST": settings["configured_controller_host"],
        "EPISODE_SERVER_PORT": settings["server_port"],
        "EPISODE_SERVER_URL": settings["server_url"],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            f"{key}={shlex.quote(str(value))}\n"
            for key, value in mapping.items()
        ),
        encoding="utf-8",
    )


def required_text(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise RuntimeError(f"SimulationStartRequest missing {name}")
    return text


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


def positive_int(*values: Any, default: int) -> int:
    value = int_value(*values)
    return value if value > 0 else max(1, int(default))


def bool_value(*values: Any, default: bool) -> bool:
    for value in values:
        if value is None:
            continue
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
    return bool(default)


def optional_bool(*values: Any) -> bool | None:
    for value in values:
        if value is None or str(value).strip() == "":
            continue
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
    return None


def safe_part(value: Any) -> str:
    text = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value or "").strip()).strip("._")
    return text or "item"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--env-out", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.request, args.output, args.env_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
