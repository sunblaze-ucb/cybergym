import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import docker
import json

client = docker.from_env()


def pull_images(repo, tags, max_workers=1):
    def _pull(tag):
        image = f"{repo}:{tag}"
        print(f"Pulling {image}...")
        try:
            client.images.pull(repo, tag=tag)
            print(f"Successfully pulled {image}")
        except docker.errors.APIError as e:
            print(f"Failed to pull {image}: {e}")

    if max_workers == 1:
        for tag in tags:
            _pull(tag)
        return

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_pull, tag): tag for tag in tags}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                tag = futures[future]
                print(f"Unexpected error pulling {repo}:{tag}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download the server data.")
    parser.add_argument(
        "--tasks-file", "-f", default="tasks.json", help="Path to file containing tags (default: arvo-ids.txt)"
    )
    parser.add_argument(
        "--max-workers", "-w", type=int, default=1, help="Maximum number of concurrent workers (default: 1)"
    )
    args = parser.parse_args()

    pull_images("cybergym/oss-fuzz-base-runner", ["latest"], 1)

    with open(args.tasks_file) as f:
        tasks = json.load(f)
    tags_arvo = []
    tags_ossfuzz = []
    for task in tasks:
        if task["task_id"].split(":")[0] == "arvo":
            arvo_id = task["task_id"].split(":")[-1]
            tags_arvo.append(f"{arvo_id}-vul")
            tags_arvo.append(f"{arvo_id}-fix")
        if task["task_id"].split(":")[0] == "ossfuzz":
            ossfuzz_id = task["task_id"].split(":")[-1]
            tags_ossfuzz.append(f"{ossfuzz_id}-vul")
            tags_ossfuzz.append(f"{ossfuzz_id}-fix")
    if tags_arvo:
        pull_images("n132/arvo", tags_arvo, args.max_workers)
    if tags_ossfuzz:
        pull_images("cybergym/oss-fuzz", tags_ossfuzz, args.max_workers)
