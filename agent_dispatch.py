#!/usr/bin/env python3
"""Run one of CyberGym's example-agent harnesses with normalized settings."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any


def text(value: Any) -> str:
    return str(value or "").strip()


def common_args(settings: dict[str, Any], server: str) -> list[str]:
    return [
        "--task_id", settings["task_id"],
        "--data_dir", settings["data_dir"],
        "--server", server,
        "--difficulty", settings["difficulty"],
    ]


def command_for(settings: dict[str, Any], runner_tmp: Path, server: str, timeout: int) -> list[str]:
    python = text(settings.get("python_bin")) or "python3.12"
    runner = settings["agent_runner"]
    agent_type = settings["agent_type"]
    command = [python, runner]
    if agent_type == "openhands":
        from openhands_prepare import stage_adapter

        staged_runner, _ = stage_adapter(
            source_runner=Path(runner),
            destination=runner_tmp / "openhands-adapter",
            runtime_image=settings["agent_image"],
            runtime_host=settings["runtime_host"],
        )
        command[1] = str(staged_runner)
        command += [
            "--log_dir", settings["logs_dir"], "--tmp_dir", settings["tmp_dir"],
            "--llm.model", settings["model_ref"],
            "--llm.api_key", settings["gateway_api_key"],
            "--llm.base_url", settings["gateway_url"],
            "--llm.top_p", str(settings["top_p"]),
            "--llm.temperature", str(settings["temperature"]),
            "--llm.max_output_tokens", str(settings["max_output_tokens"]),
            "--max_iter", str(settings["max_iter"]), "--timeout", str(timeout),
            "--repo", settings["openhands_repo"],
        ]
        if settings.get("native_tool_calling") is not None:
            command += ["--llm.native_tool_calling", str(settings["native_tool_calling"]).lower()]
        command += ["--silent", str(bool(settings.get("silent"))).lower()]
    elif agent_type in {"claude_code", "codex", "opencode"}:
        model = settings["model_ref"]
        if agent_type in {"claude_code", "codex"} and "/" in model:
            model = model.split("/", 1)[1]
        command += [
            "--model", model,
            "--log_dir", settings["logs_dir"], "--tmp_dir", settings["tmp_dir"],
            "--max_iter", str(settings["max_iter"]), "--timeout", str(timeout),
            "--image_name", settings["agent_image"],
        ]
        if agent_type == "opencode":
            command += ["--base_url", settings["gateway_url"]]
        elif agent_type == "claude_code":
            command += ["--base_url", settings["gateway_url"]]
    else:
        raise RuntimeError(f"Unsupported CyberGym agent_type: {agent_type}")
    return command + common_args(settings, server)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--episode", type=Path, required=True)
    parser.add_argument("--runner-tmp", type=Path, required=True)
    parser.add_argument("--runtime-host", required=True)
    parser.add_argument("--agent-server-url", required=True)
    parser.add_argument("--timeout", type=int, required=True)
    args = parser.parse_args()
    settings = json.loads(args.episode.read_text(encoding="utf-8"))
    settings["runtime_host"] = args.runtime_host
    command = command_for(settings, args.runner_tmp, args.agent_server_url, args.timeout)
    print(
        f"Dispatching CyberGym agent_type={settings['agent_type']} "
        f"model={settings['model_ref']} task={settings['task_id']}",
        flush=True,
    )
    env = os.environ.copy()
    env.update({
        "OPENAI_API_KEY": settings["gateway_api_key"],
        "LLM_API_KEY": settings["gateway_api_key"],
        "OPENAI_BASE_URL": settings["gateway_url"],
        "LLM_BASE_URL": settings["gateway_url"],
        "ANTHROPIC_API_KEY": settings["gateway_api_key"],
        "ANTHROPIC_AUTH_TOKEN": settings["gateway_api_key"],
        "ANTHROPIC_BASE_URL": settings["gateway_url"],
    })
    # Keep a guard around the harness itself.  Without this, a harness can
    # leave subprocess.run waiting after its child has been terminated and the
    # outer runner loses the chance to emit a truncated result.
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            env=env,
            check=False,
            timeout=max(1, int(args.timeout) + 45),
        )
        returncode = int(completed.returncode)
    except subprocess.TimeoutExpired as error:
        elapsed = time.monotonic() - started
        print(
            f"CyberGym agent harness timed out: elapsed={elapsed:.1f}s "
            f"timeout={args.timeout}s error={error}",
            flush=True,
        )
        return 124

    elapsed = time.monotonic() - started
    # 143 is SIGTERM (128+15).  When it occurs at the configured timeout,
    # normalize it to timeout status so runner.sh/result_writer classify it as
    # a truncated rollout with zero reward rather than a generic failure.
    if returncode == 143 and elapsed >= max(0, int(args.timeout) - 5):
        print(
            f"CyberGym agent harness received SIGTERM at timeout: "
            f"elapsed={elapsed:.1f}s timeout={args.timeout}s",
            flush=True,
        )
        return 124
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
