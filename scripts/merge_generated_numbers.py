import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

RAW_FILE = BASE_DIR / "data" / "raw-source-database.json"
GENERATED_FILE = BASE_DIR / "data" / "generated-numbers.json"


def main():

    with open(RAW_FILE, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    with open(GENERATED_FILE, "r", encoding="utf-8") as f:
        generated_data = json.load(f)

    raw_numbers = raw_data["numbers"]

    existing_numbers = {entry["number"] for entry in raw_numbers}

    new_entries = []

    for number in generated_data["numbers"]:

        if number in existing_numbers:
            continue

        entry = {
            "number": number,
            "category": "unknown",
            "reports": 0,
            "last_seen_days": 999,
            "prefix_official": True,
            "scam_flag": False,
            "source_confidence": 0.4
        }

        new_entries.append(entry)

    raw_numbers.extend(new_entries)

    with open(RAW_FILE, "w", encoding="utf-8") as f:
        json.dump(raw_data, f, indent=2)

    print("Merged numbers:", len(new_entries))


if __name__ == "__main__":
    main()
