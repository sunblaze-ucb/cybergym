import os
from pathlib import Path

from pydantic_core import to_json


def save_json(obj, path, indent=None, **kwargs):
    """
    Save a JSON object to a file.
    """
    with open(path, "wb") as f:
        f.write(to_json(obj, indent=indent, **kwargs))


def get_arvo_id(task_id: str):
    return task_id.split(":")[1]


def get_oss_fuzz_id(task_id: str):
    return task_id.split(":")[1]


def get_docker_client():
    """Return a Docker API client, transparently supporting rootless podman.

    Resolution order:

    1. ``$DOCKER_HOST`` if set (``docker.from_env`` honors it verbatim).
    2. The default Docker socket at ``/var/run/docker.sock`` if it exists.
    3. A rootless podman socket at ``$XDG_RUNTIME_DIR/podman/podman.sock``
       (podman serves a Docker-compatible API there), so the same code runs
       unchanged under podman.

    Otherwise fall back to ``docker.from_env`` so its usual connection error
    surfaces.
    """
    import docker

    if not os.environ.get("DOCKER_HOST") and not Path("/var/run/docker.sock").exists():
        runtime_dir = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
        podman_sock = Path(runtime_dir) / "podman" / "podman.sock"
        if podman_sock.exists():
            return docker.DockerClient(base_url=f"unix://{podman_sock}", version="auto")
    return docker.from_env()
