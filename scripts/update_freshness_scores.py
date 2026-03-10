import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT = BASE_DIR / "data" / "scored-database.json"
OUTPUT = BASE_DIR / "data" / "scored-database.json"

NOW = datetime.utcnow()

def freshness_bonus(last_seen):
    d = datetime.strptime(last_seen, "%Y-%m-%d")
    delta = (NOW - d).days

    if delta <= 7:
        return 10
    if delta <= 30:
        return 5
    if delta <= 90:
        return 2
    if delta <= 180:
        return 0
    return -10


with INPUT.open() as f:
    data = json.load(f)

for n in data["numbers"]:
    bonus = freshness_bonus(n["last_seen"])
    n["score"] = max(0, min(100, n["score"] + bonus))

with OUTPUT.open("w") as f:
    json.dump(data, f, indent=2)

print("Freshness scores updated")
