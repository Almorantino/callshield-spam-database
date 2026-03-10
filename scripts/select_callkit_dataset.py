import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SCORED_FILE = BASE_DIR / "data" / "scored-database.json"
DEVICE_FILE = BASE_DIR / "data" / "device-database.json"

MAX_ENTRIES = 2_000_000
BLOCK_RATIO = 0.6
IDENTIFY_RATIO = 0.4


def main():
    with open(SCORED_FILE, "r", encoding="utf-8") as f:
        scored = json.load(f)

    numbers = scored["numbers"]

    blocks = [n for n in numbers if n["action"] == "block"]
    identifies = [n for n in numbers if n["action"] == "identify"]

    blocks.sort(key=lambda x: (-x["score"], -x["reports"]))
    identifies.sort(key=lambda x: (-x["score"], -x["reports"]))

    max_blocks = int(MAX_ENTRIES * BLOCK_RATIO)
    max_identifies = int(MAX_ENTRIES * IDENTIFY_RATIO)

    blocks = blocks[:max_blocks]
    identifies = identifies[:max_identifies]

    device = {
        "version": scored["version"],
        "generated_at": scored["generated_at"],
        "total_scored": scored["total_numbers"],
        "blocked_numbers": [n["number"] for n in blocks],
        "identified_numbers": [
            {"number": n["number"], "label": n["label"]} for n in identifies
        ],
    }

    with open(DEVICE_FILE, "w", encoding="utf-8") as f:
        json.dump(device, f, indent=2, ensure_ascii=False)

    print("Device dataset generated")
    print("Blocked:", len(device["blocked_numbers"]))
    print("Identify:", len(device["identified_numbers"]))


if __name__ == "__main__":
    main()
