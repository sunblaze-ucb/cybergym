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
