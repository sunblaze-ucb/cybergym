import json
from pathlib import Path
from uuid import uuid4

_forward_map: dict[str, str] = {}  # real_task_id -> masked_id
_reverse_map: dict[str, str] = {}  # masked_id -> real_task_id


def load_mask_map(path: Path):
    """Load a task ID mapping from a JSON file."""
    with open(path) as f:
        data = json.load(f)
    # Mutate in-place so existing references (from `from mask import _reverse_map`) stay valid
    _forward_map.clear()
    _forward_map.update(data)
    _reverse_map.clear()
    _reverse_map.update({v: k for k, v in data.items()})


def mask_task_id(task_id: str) -> str:
    """Look up the masked ID for a real task_id."""
    if task_id not in _forward_map:
        raise ValueError(f"Task ID not in mask map: {task_id}")
    return _forward_map[task_id]


def unmask_task_id(masked_id: str) -> str:
    """Look up the real task_id for a masked ID."""
    if masked_id not in _reverse_map:
        raise ValueError(f"Masked ID not in mask map: {masked_id}")
    return _reverse_map[masked_id]


def generate_mask_map(task_ids: list[str], output_path: Path):
    """Generate a mapping file for a list of task IDs using 12-char UUIDs."""
    mapping = {task_id: uuid4().hex[:12] for task_id in task_ids}
    with open(output_path, "w") as f:
        json.dump(mapping, f, indent=2)
    return mapping
