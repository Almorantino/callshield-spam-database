import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_FILE = BASE_DIR / "data" / "generated-numbers.json"

PREFIXES = [
    "0162",
    "0377",
    "0948"
]

COUNT_PER_PREFIX = 1000


def generate_numbers(prefix, count):
    numbers = []
    for i in range(count):
        suffix = str(i).zfill(6)
        numbers.append(prefix + suffix)
    return numbers


def main():
    all_numbers = []

    for prefix in PREFIXES:
        nums = generate_numbers(prefix, COUNT_PER_PREFIX)
        all_numbers.extend(nums)

    result = {
        "generated": len(all_numbers),
        "numbers": all_numbers
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(result, f, indent=2)

    print("Generated numbers:", len(all_numbers))


if __name__ == "__main__":
    main()
