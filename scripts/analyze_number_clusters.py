import json
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path(__file__).resolve().parent.parent
SCORED_FILE = BASE_DIR / "data" / "scored-database.json"
OUTPUT_FILE = BASE_DIR / "data" / "cluster-analysis.json"


def main():

    with open(SCORED_FILE, "r", encoding="utf-8") as f:
        scored = json.load(f)

    clusters = defaultdict(lambda: {
        "total": 0,
        "block": 0,
        "identify": 0,
        "ignore": 0
    })

    for entry in scored["numbers"]:

        number = entry["number"]
        prefix = number[:4]

        clusters[prefix]["total"] += 1
        clusters[prefix][entry["action"]] += 1

    results = []

    for prefix, stats in clusters.items():

        risk_score = stats["block"] * 5 + stats["identify"] * 2

        results.append({
            "prefix": prefix,
            "total_numbers": stats["total"],
            "block": stats["block"],
            "identify": stats["identify"],
            "ignore": stats["ignore"],
            "cluster_risk_score": risk_score
        })

    results.sort(key=lambda x: x["cluster_risk_score"], reverse=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("Cluster analysis written to cluster-analysis.json")
    print("Clusters analyzed:", len(results))


if __name__ == "__main__":
    main()
