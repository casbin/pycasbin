import json
import os
import sys
import datetime
import re


def normalize_name(name):
    name = re.sub(r"^test_benchmark_", "", name)
    parts = name.split("_")
    new_parts = []
    for p in parts:
        if p.lower() in ["rbac", "abac", "acl", "api", "rest"]:
            new_parts.append(p.upper())
        else:
            new_parts.append(p.capitalize())
    return "".join(new_parts)


def main():
    if len(sys.argv) < 3:
        print("Usage: python format_benchmark_data.py input.json output.json")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading {input_path}: {e}")
        sys.exit(1)

    # Get commit info from environment variables
    # These should be set in the GitHub Action
    commit_info = {
        "author": {
            "email": os.environ.get("COMMIT_AUTHOR_EMAIL", ""),
            "name": os.environ.get("COMMIT_AUTHOR_NAME", ""),
            "username": os.environ.get("COMMIT_AUTHOR_USERNAME", ""),
        },
        "committer": {
            "email": os.environ.get("COMMIT_COMMITTER_EMAIL", ""),
            "name": os.environ.get("COMMIT_COMMITTER_NAME", ""),
            "username": os.environ.get("COMMIT_COMMITTER_USERNAME", ""),
        },
        "distinct": True,  # Assuming true for push to master
        "id": os.environ.get("COMMIT_ID", ""),
        "message": os.environ.get("COMMIT_MESSAGE", ""),
        "timestamp": os.environ.get("COMMIT_TIMESTAMP", ""),
        "tree_id": os.environ.get("COMMIT_TREE_ID", ""),
        "url": os.environ.get("COMMIT_URL", ""),
    }

    # Get CPU count
    cpu_count = data.get("machine_info", {}).get("cpu", {}).get("count")
    if not cpu_count:
        cpu_count = os.cpu_count() or 1

    benches = []
    for bench in data.get("benchmarks", []):
        # Convert mean (seconds) to ns
        val_ns = bench["stats"]["mean"] * 1e9

        # Format extra info
        total_ops = bench["stats"]["rounds"] * bench["stats"]["iterations"]
        extra = f"{total_ops} times"

        # Create entry
        benches.append(
            {"name": normalize_name(bench["name"]), "value": round(val_ns, 2), "unit": "ns/op", "extra": extra}
        )

    output_data = {
        "commit": commit_info,
        "date": int(datetime.datetime.now().timestamp() * 1000),  # Current timestamp in ms
        "tool": "python",
        "procs": cpu_count,
        "benches": benches,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"Successfully formatted benchmark data to {output_path}")


if __name__ == "__main__":
    main()
