#!/usr/bin/env python3
"""Stage CyberGym's OpenHands adapter without mutating the image source."""
from __future__ import annotations

import argparse
import shutil
import tomllib
from pathlib import Path
from urllib.parse import urlsplit


def stage_adapter(
    *,
    source_runner: Path,
    destination: Path,
    runtime_image: str,
    runtime_host: str,
) -> tuple[Path, Path]:
    source_template = source_runner.parent / "template"
    destination.mkdir(parents=True, exist_ok=True)
    staged_runner = destination / source_runner.name
    staged_template = destination / "template"
    shutil.copy2(source_runner, staged_runner)
    shutil.copytree(source_template, staged_template, dirs_exist_ok=True)

    config_path = staged_template / "config.toml"
    with config_path.open("rb") as config_file:
        config = tomllib.load(config_file)
    sandbox = config.get("sandbox")
    if not isinstance(sandbox, dict):
        raise RuntimeError(f"OpenHands template is missing [sandbox]: {config_path}")

    sandbox["runtime_container_image"] = runtime_image
    sandbox["runtime_binding_address"] = "0.0.0.0"
    sandbox["local_runtime_url"] = f"http://{host_only(runtime_host)}"
    docker_kwargs = sandbox.get("docker_runtime_kwargs")
    if not isinstance(docker_kwargs, dict):
        docker_kwargs = {}
        sandbox["docker_runtime_kwargs"] = docker_kwargs
    docker_kwargs["auto_remove"] = True

    try:
        import tomli_w
    except ImportError as exc:
        raise RuntimeError(
            "The CyberGym controller image must provide tomli-w for OpenHands configuration"
        ) from exc
    config_path.write_text(tomli_w.dumps(config), encoding="utf-8")
    return staged_runner, config_path


def host_only(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlsplit(text if "://" in text else f"//{text}")
    return str(parsed.hostname or text).strip("[]")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-runner", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--runtime-host", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    staged_runner, config_path = stage_adapter(
        source_runner=args.source_runner,
        destination=args.destination,
        runtime_image=args.runtime_image,
        runtime_host=args.runtime_host,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        f"EPISODE_STAGED_OPENHANDS_RUNNER={shlex_quote(str(staged_runner))}\n"
        f"EPISODE_STAGED_OPENHANDS_CONFIG={shlex_quote(str(config_path))}\n",
        encoding="utf-8",
    )
    return 0


def shlex_quote(value: str) -> str:
    import shlex

    return shlex.quote(value)


if __name__ == "__main__":
    raise SystemExit(main())
