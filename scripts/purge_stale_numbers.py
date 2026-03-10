import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT = BASE_DIR / "data" / "scored-database.json"
OUTPUT = BASE_DIR / "data" / "scored-database.json"

NOW = datetime.utcnow()

STALE_DAYS = 180


def is_stale(last_seen):
    d = datetime.strptime(last_seen, "%Y-%m-%d")
    return (NOW - d).days > STALE_DAYS


with INPUT.open() as f:
    data = json.load(f)

before = len(data["numbers"])

data["numbers"] = [
    n for n in data["numbers"]
    if not is_stale(n["last_seen"])
]

after = len(data["numbers"])

with OUTPUT.open("w") as f:
    json.dump(data, f, indent=2)

print(f"Purged stale numbers: {before - after}")
print(f"Remaining numbers: {after}")
