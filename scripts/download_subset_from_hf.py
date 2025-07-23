import argparse
from huggingface_hub import hf_hub_download
import shutil
import os


def move_file(src_path, dest_path):
    """Move a file from src_path to dest_path and delete the source file.

    Args:
        src_path (str): The path of the source file.
        dest_path (str): The path of the destination file.
    """
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    shutil.copy2(src_path, dest_path)
    try:
        os.remove(src_path)
    except Exception as e:
        print(f"  Warning: Could not delete cache file {src_path}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Download datasets from HuggingFace and organize them into a specified data directory."
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="cybergym_data",
        help="Name of the data directory (default: cybergym_data)",
    )
    args = parser.parse_args()
    data_dir = args.data_dir

    repo_id = "sunblaze-ucb/cybergym"
    dataset_to_folder = {
        "arvo": ["3938", "24993", "1065", "10400", "368"],
        "oss-fuzz": ["42535201", "42535468", "370689421", "385167047"],
    }

    file_names = [
        "description.txt",
        "error.txt",
        "patch.diff",
        "repo-fix.tar.gz",
        "repo-vul.tar.gz",
    ]

    # Download root tasks.json to current directory and delete cache
    src = hf_hub_download(
        repo_id=repo_id, repo_type="dataset", filename="tasks.json"
    )
    move_file(src, f"{data_dir}/tasks.json")

    for dataset, folders in dataset_to_folder.items():
        for folder in folders:
            for file in file_names:
                remote_path = f"data/{dataset}/{folder}/{file}"
                local_path = os.path.join(
                    data_dir, "data", dataset, folder, file
                )
                print(f"[{dataset}] Downloading {remote_path} ...")
                try:
                    src = hf_hub_download(
                        repo_id=repo_id,
                        repo_type="dataset",
                        filename=remote_path,
                    )
                    print(f"  Success: {src} -> {local_path}")
                    move_file(src, local_path)
                except Exception as e:
                    print(f"  Failed: {e}")


if __name__ == "__main__":
    main()
