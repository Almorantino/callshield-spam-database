from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

BASE_DIR = Path(__file__).resolve().parent.parent
SOURCES_DIR = BASE_DIR / "sources"
DATA_DIR = BASE_DIR / "data"

FEEDS_PATH = SOURCES_DIR / "feeds.json"
SCAM_DOMAINS_PATH = SOURCES_DIR / "scam-domains-normalized.json"
URL_REPORTS_PATH = SOURCES_DIR / "url-reports.json"
SAFE_WEBSITES_PATH = SOURCES_DIR / "safe-websites.json"
WARNINGLIST_DOMAINS_PATH = SOURCES_DIR / "warninglist-domains.json"
LOCAL_DB_PATH = DATA_DIR / "callshield.db"
OUTPUT_PATH = SOURCES_DIR / "url-evidence.json"

DOMAIN_REGEX = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:fr|com|net|org|eu|info|biz|co|io|app|xyz|top|click|ru|cn)\b",
    re.IGNORECASE,
)
URL_REGEX = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
TRAILING_URL_PUNCTUATION = '.,;:!?)\\]}>"\''
DOMAIN_ALLOWED_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def normalize_domain(raw: object) -> Optional[str]:
    value = str(raw or "").strip().lower()
    if not value:
        return None

    value = re.sub(r"^https?://", "", value)
    if value.startswith("www."):
        value = value[4:]

    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip(".")
    if not value or "." not in value or " " in value:
        return None

    labels = value.split(".")
    if any(not label for label in labels):
        return None

    for label in labels:
        if label.startswith("-") or label.endswith("-"):
            return None
        if any(ch not in DOMAIN_ALLOWED_CHARS for ch in label):
            return None

    return value


def root_domain(raw: object) -> Optional[str]:
    domain = normalize_domain(raw)
    if not domain:
        return None

    parts = [part for part in domain.split(".") if part]
    if len(parts) < 2:
        return None

    return ".".join(parts[-2:])


def normalize_url(raw: object) -> Optional[str]:
    value = str(raw or "").strip().rstrip(TRAILING_URL_PUNCTUATION)
    if not value.startswith(("http://", "https://")):
        return None
    return value


def domain_from_url(raw: object) -> Optional[str]:
    url = normalize_url(raw)
    if not url:
        return None
    return normalize_domain(url)


def extract_domains(values: Iterable[object]) -> List[str]:
    results: List[str] = []
    seen: Set[str] = set()

    for value in values:
        if value is None:
            continue
        direct = normalize_domain(value)
        candidates = [direct] if direct else []
        if not direct:
            candidates = [normalize_domain(match) for match in DOMAIN_REGEX.findall(str(value))]

        for candidate in candidates:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            results.append(candidate)

    return results


def extract_urls(values: Iterable[object]) -> List[str]:
    results: List[str] = []
    seen: Set[str] = set()

    for value in values:
        if value is None:
            continue
        direct = normalize_url(value)
        candidates = [direct] if direct else []
        if not direct:
            candidates = [normalize_url(match) for match in URL_REGEX.findall(str(value))]

        for candidate in candidates:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            results.append(candidate)

    return results


def load_feed_profiles() -> Dict[str, dict]:
    payload = load_json(FEEDS_PATH, {"feeds": []})
    profiles: Dict[str, dict] = {}
    for feed in payload.get("feeds", []):
        if not isinstance(feed, dict):
            continue
        feed_id = str(feed.get("id") or "").strip()
        if feed_id:
            profiles[feed_id] = feed
    return profiles


def load_safe_domains() -> Set[str]:
    safe: Set[str] = set()
    payload = load_json(SAFE_WEBSITES_PATH, {"domains": []})
    for row in payload.get("domains", []):
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "").strip().lower()
        if status and status != "active":
            continue
        for value in (row.get("domain"), row.get("root_domain")):
            domain = normalize_domain(value)
            if domain:
                safe.add(domain)
            root = root_domain(value)
            if root:
                safe.add(root)
    return safe


def load_warninglist_domains() -> Set[str]:
    payload = load_json(WARNINGLIST_DOMAINS_PATH, {"domains": []})
    rows = payload.get("domains", []) if isinstance(payload, dict) else []
    results: Set[str] = set()
    for row in rows:
        value = row.get("domain") if isinstance(row, dict) else row
        domain = normalize_domain(value)
        if domain:
            results.add(domain)
        root = root_domain(value)
        if root:
            results.add(root)
    return results


def load_trusted_safe_domains() -> Set[str]:
    if not LOCAL_DB_PATH.exists():
        return set()

    results: Set[str] = set()
    try:
        conn = sqlite3.connect(str(LOCAL_DB_PATH))
        rows = conn.execute(
            """
            SELECT domain, root_domain, status, trust_level, trust_score
            FROM trusted_domains
            WHERE domain IS NOT NULL
            """
        ).fetchall()
    except Exception:
        return set()
    finally:
        try:
            conn.close()
        except Exception:
            pass

    for domain_value, root_value, status, trust_level, trust_score in rows:
        normalized_status = str(status or "").strip().lower()
        normalized_level = str(trust_level or "").strip().lower()
        score = float(trust_score or 0)
        if normalized_status == "fraud":
            continue
        if normalized_status != "active" and normalized_level not in {"verified", "high"} and score < 80:
            continue
        for value in (domain_value, root_value):
            domain = normalize_domain(value)
            if domain:
                results.add(domain)
            root = root_domain(value)
            if root:
                results.add(root)
    return results


def is_excluded_domain(domain: str, excluded_domains: Set[str]) -> bool:
    normalized = normalize_domain(domain)
    root = root_domain(domain)
    return bool(normalized and normalized in excluded_domains) or bool(root and root in excluded_domains)


def freshness_from_seen(last_seen: str, ttl_hours: int) -> str:
    if not last_seen:
        return "unknown"
    try:
        seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except Exception:
        return "unknown"

    age_hours = max(0.0, (datetime.now(timezone.utc) - seen).total_seconds() / 3600)
    if age_hours <= ttl_hours:
        return "fresh"
    if age_hours <= ttl_hours * 3:
        return "aging"
    return "stale"


def canonical_category(value: object) -> str:
    category = str(value or "").strip().lower()
    if category in {"phishing_url", "malware_url", "official_ioc", "smishing_report"}:
        return category
    if category in {"fraud", "scam", "phishing"}:
        return "phishing_url"
    return "unknown"


def source_profile(source_id: str, profiles: Dict[str, dict]) -> dict:
    if source_id in profiles:
        return profiles[source_id]
    return {
        "id": source_id,
        "confidence_score": 0.6,
        "ttl_hours": 72,
        "category": "phishing_url",
        "allowed_usage": "external_url_evidence",
    }


def source_ids_from_detail(source_detail: str) -> List[str]:
    detail = str(source_detail or "").strip().lower()
    if "openphish" in detail and "phishing_army" in detail:
        # The current normalized source file stores merged rows after feed-level
        # dedupe, so this remains one corroboration source until raw feed
        # provenance is preserved per domain.
        return ["public_feed_normalized"]
    if "openphish" in detail:
        return ["openphish_public"]
    if "phishing_army" in detail:
        return ["phishing_army_blocklist"]
    return ["public_feed_normalized"]


class EvidenceAccumulator:
    def __init__(self, excluded_domains: Set[str]):
        self.excluded_domains = excluded_domains
        self.domains: Dict[str, dict] = {}
        self.urls: Dict[str, dict] = {}
        self.excluded_safe = 0

    def add_domain(self, domain_value: object, category: object, source_id: str, confidence: float, ttl_hours: int,
                   source_detail: str = "", first_seen: str = "", last_seen: str = "", evidence_count: int = 1,
                   brand_target: str = "") -> None:
        domain = normalize_domain(domain_value)
        root = root_domain(domain_value)
        if not domain or not root:
            return
        if is_excluded_domain(domain, self.excluded_domains):
            self.excluded_safe += 1
            return

        row = self.domains.setdefault(domain, {
            "domain": domain,
            "root_domain": root,
            "category": canonical_category(category),
            "confidence": 0.0,
            "freshness": "unknown",
            "source_count": 0,
            "evidence_count": 0,
            "sources": [],
            "source_details": [],
            "first_seen": "",
            "last_seen": "",
            "ttl_hours": ttl_hours,
            "brand_target": brand_target or "",
        })

        if source_id not in row["sources"]:
            row["sources"].append(source_id)
            row["source_count"] = len(row["sources"])
        if source_detail and source_detail not in row["source_details"]:
            row["source_details"].append(source_detail)

        row["confidence"] = round(max(float(row["confidence"]), float(confidence)), 4)
        row["evidence_count"] += max(1, int(evidence_count or 1))
        row["ttl_hours"] = min(int(row["ttl_hours"] or ttl_hours), int(ttl_hours or row["ttl_hours"] or 72))
        row["category"] = row["category"] if row["category"] != "unknown" else canonical_category(category)
        row["first_seen"] = min(filter(None, [row["first_seen"], first_seen]), default="")
        row["last_seen"] = max(filter(None, [row["last_seen"], last_seen]), default="")
        row["freshness"] = freshness_from_seen(row["last_seen"], int(row["ttl_hours"] or 72))

    def add_url(self, url_value: object, category: object, source_id: str, confidence: float, ttl_hours: int,
                source_detail: str = "", first_seen: str = "", last_seen: str = "", evidence_count: int = 1) -> None:
        url = normalize_url(url_value)
        if not url:
            return
        domain = domain_from_url(url)
        root = root_domain(domain)
        if not domain or not root:
            return
        if is_excluded_domain(domain, self.excluded_domains):
            self.excluded_safe += 1
            return

        row = self.urls.setdefault(url, {
            "url": url,
            "domain": domain,
            "root_domain": root,
            "category": canonical_category(category),
            "confidence": 0.0,
            "freshness": "unknown",
            "source_count": 0,
            "evidence_count": 0,
            "sources": [],
            "source_details": [],
            "first_seen": "",
            "last_seen": "",
            "ttl_hours": ttl_hours,
        })

        if source_id not in row["sources"]:
            row["sources"].append(source_id)
            row["source_count"] = len(row["sources"])
        if source_detail and source_detail not in row["source_details"]:
            row["source_details"].append(source_detail)

        row["confidence"] = round(max(float(row["confidence"]), float(confidence)), 4)
        row["evidence_count"] += max(1, int(evidence_count or 1))
        row["ttl_hours"] = min(int(row["ttl_hours"] or ttl_hours), int(ttl_hours or row["ttl_hours"] or 72))
        row["category"] = row["category"] if row["category"] != "unknown" else canonical_category(category)
        row["first_seen"] = min(filter(None, [row["first_seen"], first_seen]), default="")
        row["last_seen"] = max(filter(None, [row["last_seen"], last_seen]), default="")
        row["freshness"] = freshness_from_seen(row["last_seen"], int(row["ttl_hours"] or 72))


def add_scam_domain_evidence(accumulator: EvidenceAccumulator, profiles: Dict[str, dict]) -> int:
    payload = load_json(SCAM_DOMAINS_PATH, {"domains": []})
    generated_at = str(payload.get("generated_at") or "")
    rows = payload.get("domains", [])
    added = 0
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        source_detail = str(row.get("source_detail") or row.get("source") or "public_feed_normalized")
        for source_id in source_ids_from_detail(source_detail):
            profile = source_profile(source_id, profiles)
            accumulator.add_domain(
                domain_value=row.get("domain"),
                category=profile.get("category") or row.get("category"),
                source_id=source_id,
                confidence=float(profile.get("confidence_score") or 0.6),
                ttl_hours=int(profile.get("ttl_hours") or 72),
                source_detail=source_detail,
                first_seen=generated_at,
                last_seen=generated_at,
                evidence_count=1,
            )
            added += 1
    return added


def add_url_report_evidence(accumulator: EvidenceAccumulator) -> int:
    payload = load_json(URL_REPORTS_PATH, {"domains": [], "urls": []})
    added = 0

    for row in payload.get("domains", []) if isinstance(payload.get("domains"), list) else []:
        if not isinstance(row, dict):
            continue
        report_count = int(row.get("reports_count") or 1)
        confidence = min(0.75, 0.45 + report_count * 0.1)
        accumulator.add_domain(
            domain_value=row.get("domain"),
            category="smishing_report",
            source_id="local_url_reports",
            confidence=confidence,
            ttl_hours=168,
            source_detail="community_url_reports",
            evidence_count=report_count,
        )
        added += 1

    for row in payload.get("urls", []) if isinstance(payload.get("urls"), list) else []:
        if not isinstance(row, dict):
            continue
        report_count = int(row.get("reports_count") or 1)
        confidence = min(0.75, 0.45 + report_count * 0.1)
        accumulator.add_url(
            url_value=row.get("url"),
            category="smishing_report",
            source_id="local_url_reports",
            confidence=confidence,
            ttl_hours=168,
            source_detail="community_url_reports",
            evidence_count=report_count,
        )
        added += 1

    return added


def build_payload(accumulator: EvidenceAccumulator, inputs: Dict[str, int]) -> dict:
    domains = sorted(accumulator.domains.values(), key=lambda row: (row["root_domain"], row["domain"]))
    urls = sorted(accumulator.urls.values(), key=lambda row: (row["root_domain"], row["url"]))
    return {
        "schema_version": "url_evidence_v1",
        "generated_at": utc_now_iso(),
        "policy": {
            "usage": "evidence_only",
            "direct_blocking_allowed": False,
            "trusted_domain_promotion_allowed": False,
            "requires_corroboration_for_scoring": True,
        },
        "inputs": inputs,
        "counts": {
            "domains": len(domains),
            "urls": len(urls),
            "excluded_safe_or_warninglisted": accumulator.excluded_safe,
        },
        "domains": domains,
        "urls": urls,
    }


def main() -> None:
    profiles = load_feed_profiles()
    excluded_domains = set()
    excluded_domains.update(load_safe_domains())
    excluded_domains.update(load_trusted_safe_domains())
    excluded_domains.update(load_warninglist_domains())

    accumulator = EvidenceAccumulator(excluded_domains=excluded_domains)
    inputs = {
        "scam_domain_rows_seen": add_scam_domain_evidence(accumulator, profiles),
        "url_report_rows_seen": add_url_report_evidence(accumulator),
        "excluded_domain_count": len(excluded_domains),
    }

    payload = build_payload(accumulator, inputs)
    SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"url evidence domains={payload['counts']['domains']}")
    print(f"url evidence urls={payload['counts']['urls']}")
    print(f"excluded_safe_or_warninglisted={payload['counts']['excluded_safe_or_warninglisted']}")
    print(f"output={OUTPUT_PATH}")


if __name__ == "__main__":
    main()
