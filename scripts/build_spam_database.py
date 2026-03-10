import json
from pathlib import Path

SOURCE_FILE = Path("spam-source-database.json")
OUTPUT_FILE = Path("spam-database.json")

LABELS = {
    "energie": "Démarchage énergie",
    "assurance": "Démarchage assurance",
    "btp": "Démarchage BTP",
    "survey": "Sondage commercial",
    "fraud": "Arnaque probable",
    "scam": "Scam probable",
    "demarchage": "Démarchage",
}

def normalize_number(value: str) -> str:
    return "".join(ch for ch in str(value) if ch.isdigit())

def label_for(category: str) -> str:
    key = (category or "").strip().lower()
    return LABELS.get(key, "Spam probable")

def should_block(entry: dict) -> bool:
    return entry.get("reports", 0) >= 10 or bool(entry.get("scam_flag", False))

def should_identify(entry: dict) -> bool:
    return entry.get("reports", 0) >= 3 or bool(entry.get("prefix_official", False))

def main() -> None:
    if not SOURCE_FILE.exists():
        raise SystemExit(
            f"❌ Fichier source introuvable: {SOURCE_FILE}\n"
            "Crée-le dans le même dossier que ce script."
        )

    with SOURCE_FILE.open("r", encoding="utf-8") as f:
        source = json.load(f)

    blocked_numbers = []
    identified_numbers = []
    seen_blocked = set()
    seen_identified = set()

    for raw in source.get("numbers", []):
        number = normalize_number(raw.get("number", ""))
        if not number:
            continue

        if should_block(raw):
            if number not in seen_blocked:
                blocked_numbers.append(number)
                seen_blocked.add(number)
            continue

        if should_identify(raw) and number not in seen_identified:
            identified_numbers.append({
                "number": number,
                "label": label_for(raw.get("category", "")),
            })
            seen_identified.add(number)

    result = {
        "version": source.get("version", 1),
        "last_updated": source.get("last_updated", ""),
        "blocked_numbers": blocked_numbers,
        "identified_numbers": identified_numbers,
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"✅ {OUTPUT_FILE.name} généré")
    print(f"   blocked_numbers: {len(blocked_numbers)}")
    print(f"   identified_numbers: {len(identified_numbers)}")

if __name__ == "__main__":
    main()