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
    pull_images("cybergym/oss-fuzz-base-runner", ["latest", "20200102", "20190802", "20220102"], 1)
