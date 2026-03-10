import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
SOURCE_FILE = BASE_DIR / "data" / "raw-source-database.json"
SCORED_FILE = BASE_DIR / "data" / "scored-database.json"
DEVICE_FILE = BASE_DIR / "data" / "device-database.json"
OUTPUT_FILE = BASE_DIR / "output" / "spam-database.json"
CLUSTER_FILE = BASE_DIR / "data" / "cluster-analysis.json"

CATEGORY_LABELS = {
    "fraud": "Arnaque probable",
    "scam": "Spam probable",
    "insurance": "Démarchage assurance",
    "assurance": "Démarchage assurance",
    "energy": "Démarchage énergie",
    "energie": "Démarchage énergie",
    "btp": "Démarchage BTP",
    "telemarketing": "Démarchage commercial",
    "demarchage": "Démarchage commercial",
    "survey": "Sondage commercial",
    "unknown": "Inconnu",
}

SOURCE_CONFIDENCE_MAP = {
    "manual_seed": 0.95,
    "official_prefix": 0.85,
    "web_scraper": 0.65,
    "community_report": 0.75,
    "unknown": 0.50,
}

def load_cluster_scores() -> dict:
    if not CLUSTER_FILE.exists():
        return {}

    with CLUSTER_FILE.open("r", encoding="utf-8") as f:
        cluster_data = json.load(f)

    scores = {}

    for entry in cluster_data:
        prefix = str(entry.get("prefix", "")).strip()
        risk_score = int(entry.get("cluster_risk_score", 0) or 0)

        if prefix:
            scores[prefix] = risk_score

    return scores


def cluster_bonus_for(number: str, cluster_scores: dict) -> int:
    prefix = number[:4]
    risk_score = cluster_scores.get(prefix, 0)

    if risk_score >= 20:
        return 10
    if risk_score >= 10:
        return 5
    if risk_score >= 5:
        return 2
    return 0

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def today_utc_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def normalize_digits(value: str) -> str:
    return "".join(ch for ch in str(value) if ch.isdigit())


def to_e164_fr(number_digits: str) -> str:
    if not number_digits:
        return ""
    if number_digits.startswith("33"):
        return f"+{number_digits}"
    if number_digits.startswith("0") and len(number_digits) == 10:
        return f"+33{number_digits[1:]}"
    if number_digits.startswith("+"):
        return number_digits
    return f"+{number_digits}"


def normalize_category(raw_category: str) -> str:
    key = (raw_category or "").strip().lower()
    aliases = {
        "assurance": "insurance",
        "energie": "energy",
        "demarchage": "telemarketing",
    }
    return aliases.get(key, key if key in {
        "fraud", "scam", "insurance", "energy", "btp", "telemarketing", "survey", "unknown"
    } else "unknown")


def label_for(category: str) -> str:
    return CATEGORY_LABELS.get(category, "Spam probable")


def normalize_sources(raw_entry: dict) -> list[str]:
    raw_source = raw_entry.get("source", [])
    if isinstance(raw_source, str):
        sources = [raw_source]
    elif isinstance(raw_source, list):
        sources = [str(item).strip() for item in raw_source if str(item).strip()]
    else:
        sources = []

    if raw_entry.get("prefix_official", False) and "official_prefix" not in sources:
        sources.append("official_prefix")

    if not sources:
        sources = ["unknown"]

    return sources


def compute_source_confidence(raw_entry: dict, sources: list[str]) -> float:
    explicit_confidence = raw_entry.get("source_confidence")
    if explicit_confidence is not None:
        try:
            value = float(explicit_confidence)
            return max(0.0, min(1.0, round(value, 2)))
        except (TypeError, ValueError):
            pass

    values = [SOURCE_CONFIDENCE_MAP.get(src, 0.50) for src in sources]
    avg = sum(values) / len(values)
    return round(max(0.0, min(1.0, avg)), 2)


def compute_score(
    reports: int,
    scam_flag: bool,
    prefix_official: bool,
    source_confidence: float,
    category: str,
    sources_count: int,
) -> int:
    score = 0

    # 1. Volume de signalements
    if reports >= 21:
        score += 45
    elif reports >= 11:
        score += 35
    elif reports >= 6:
        score += 25
    elif reports >= 3:
        score += 15
    elif reports >= 1:
        score += 5

    # 2. Nature du signal
    if scam_flag:
        score += 35

    if category == "fraud":
        score += 25
    elif category == "scam":
        score += 20
    elif category in {"energy", "insurance", "btp", "telemarketing"}:
        score += 8

    # 3. Fiabilité de la source
    if source_confidence >= 0.9:
        score += 12
    elif source_confidence >= 0.8:
        score += 10
    elif source_confidence >= 0.7:
        score += 8
    elif source_confidence >= 0.6:
        score += 6
    else:
        score += 4

    # 4. Signal structurel
    if prefix_official:
        score += 8

    # 5. Multiplicité des sources
    if sources_count >= 3:
        score += 10
    elif sources_count == 2:
        score += 5

    score = min(score, 100)

    # Garde-fou métier : ne pas surbloquer le démarchage "classique"
    if not scam_flag and category in {"energy", "insurance", "btp", "telemarketing"}:
        score = min(score, 69)

    return score


def action_for(score: int) -> str:
    if score >= 70:
        return "block"
    if score >= 30:
        return "identify"
    return "ignore"


def build_scored_entry(raw: dict, cluster_scores: dict):
    number = normalize_digits(raw.get("number", ""))
    if not number:
        return None

    reports = int(raw.get("reports", 0) or 0)
    scam_flag = bool(raw.get("scam_flag", False))
    prefix_official = bool(raw.get("prefix_official", False))
    category = normalize_category(raw.get("category", "unknown"))
    sources = normalize_sources(raw)
    source_confidence = compute_source_confidence(raw, sources)
    score = compute_score(
        reports=reports,
        scam_flag=scam_flag,
        prefix_official=prefix_official,
        source_confidence=source_confidence,
        category=category,
        sources_count=len(sources),
    )

    bonus = cluster_bonus_for(number, cluster_scores)
    score = min(100, score + bonus)

    return {
        "number": number,
        "normalized_e164": to_e164_fr(number),
        "country": "FR",
        "category": category,
        "label": label_for(category),
        "reports": reports,
        "scam_flag": scam_flag,
        "prefix_official": prefix_official,
        "source": sources,
        "source_confidence": source_confidence,
        "last_seen": raw.get("last_seen", today_utc_date()),
        "score": score,
        "action": action_for(score),
    }


def build_scored_database(source: dict) -> dict:
    seen = set()
    numbers = []
    cluster_scores = load_cluster_scores()
    for raw in source.get("numbers", []):
        entry = build_scored_entry(raw, cluster_scores)
        if not entry:
            continue

        key = entry["number"]
        if key in seen:
            continue

        seen.add(key)
        numbers.append(entry)

    numbers.sort(key=lambda item: (-item["score"], item["number"]))

    return {
        "version": "1.0",
        "generated_at": utc_now_iso(),
        "total_numbers": len(numbers),
        "numbers": numbers,
    }


def build_device_database(scored_db: dict) -> dict:
    blocked_numbers = []
    identified_numbers = []
    seen_blocked = set()
    seen_identified = set()

    for entry in scored_db.get("numbers", []):
        number = entry["number"]
        action = entry["action"]

        if action == "block":
            if number not in seen_blocked:
                blocked_numbers.append(number)
                seen_blocked.add(number)
            continue

        if action == "identify":
            if number not in seen_identified:
                identified_numbers.append({
                    "number": number,
                    "label": entry["label"],
                })
                seen_identified.add(number)

    return {
        "version": scored_db.get("version", "1.0"),
        "generated_at": scored_db.get("generated_at", utc_now_iso()),
        "total_scored": scored_db.get("total_numbers", 0),
        "blocked_numbers": blocked_numbers,
        "identified_numbers": identified_numbers,
    }


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def main() -> None:
    if not SOURCE_FILE.exists():
        raise SystemExit(
            f"❌ Fichier source introuvable: {SOURCE_FILE}\n"
            "Le fichier attendu est: data/raw-source-database.json"
        )

    with SOURCE_FILE.open("r", encoding="utf-8") as f:
        source = json.load(f)

    scored_db = build_scored_database(source)
    device_db = build_device_database(scored_db)

    write_json(SCORED_FILE, scored_db)
    write_json(DEVICE_FILE, device_db)
    write_json(OUTPUT_FILE, device_db)

    print("✅ Build terminé")
    print(f"   scored-database.json: {scored_db['total_numbers']} numéros")
    print(f"   blocked_numbers: {len(device_db['blocked_numbers'])}")
    print(f"   identified_numbers: {len(device_db['identified_numbers'])}")
    print(f"   output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
