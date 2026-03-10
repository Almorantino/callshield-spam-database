import json
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent

RAW_FILE = BASE_DIR / "data" / "raw-source-database.json"
SOURCES_DIR = BASE_DIR / "sources"

DEFAULTS = {
    "category": "unknown",
    "reports": 1,
    "last_seen_days": 0,
    "prefix_official": False,
    "scam_flag": False,
    "source_confidence": 0.6,
}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, payload):
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def normalize_entry(entry: dict, source_name: str) -> Optional[dict]:
    number = str(entry.get("number", "")).strip()
    if not number:
        return None

    result = {
        "number": number,
        "category": entry.get("category", DEFAULTS["category"]),
        "reports": int(entry.get("reports", DEFAULTS["reports"])),
        "last_seen_days": int(entry.get("last_seen_days", DEFAULTS["last_seen_days"])),
        "prefix_official": bool(entry.get("prefix_official", DEFAULTS["prefix_official"])),
        "scam_flag": bool(entry.get("scam_flag", DEFAULTS["scam_flag"])),
        "source_confidence": float(entry.get("source_confidence", DEFAULTS["source_confidence"])),
        "source": entry.get("source", source_name),
    }

    return result


def merge_entry(existing: dict, incoming: dict) -> dict:
    existing["reports"] = max(int(existing.get("reports", 0)), int(incoming.get("reports", 0)))
    existing["last_seen_days"] = min(int(existing.get("last_seen_days", 9999)), int(incoming.get("last_seen_days", 9999)))
    existing["prefix_official"] = bool(existing.get("prefix_official", False) or incoming.get("prefix_official", False))
    existing["scam_flag"] = bool(existing.get("scam_flag", False) or incoming.get("scam_flag", False))
    existing["source_confidence"] = max(
        float(existing.get("source_confidence", 0.0)),
        float(incoming.get("source_confidence", 0.0)),
    )

    if existing.get("category", "unknown") == "unknown" and incoming.get("category", "unknown") != "unknown":
        existing["category"] = incoming["category"]

    existing_source = existing.get("source", [])
    if isinstance(existing_source, str):
        existing_source = [existing_source]

    incoming_source = incoming.get("source", [])
    if isinstance(incoming_source, str):
        incoming_source = [incoming_source]

    merged_sources = sorted(set(existing_source + incoming_source))
    existing["source"] = merged_sources

    return existing


def main():
    if not RAW_FILE.exists():
        raise SystemExit(f"Missing file: {RAW_FILE}")

    SOURCES_DIR.mkdir(parents=True, exist_ok=True)

    raw_data = load_json(RAW_FILE)
    raw_numbers = raw_data.get("numbers", [])

    merged = {}
    for entry in raw_numbers:
        number = str(entry.get("number", "")).strip()
        if number:
            merged[number] = entry

    imported_files = 0
    imported_entries = 0

    for source_file in sorted(SOURCES_DIR.glob("*.json")):
        source_name = source_file.stem
        payload = load_json(source_file)
        entries = payload.get("numbers", [])

        imported_files += 1

        for entry in entries:
            normalized = normalize_entry(entry, source_name)
            if not normalized:
                continue

            number = normalized["number"]

            if number in merged:
                merged[number] = merge_entry(merged[number], normalized)
            else:
                merged[number] = normalized

            imported_entries += 1

    raw_data["numbers"] = list(merged.values())
    save_json(RAW_FILE, raw_data)

    print(f"Imported source files: {imported_files}")
    print(f"Imported entries processed: {imported_entries}")
    print(f"Total raw numbers: {len(raw_data['numbers'])}")


if __name__ == "__main__":
    main()
