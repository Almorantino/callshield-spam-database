from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set
from urllib.error import URLError
from urllib.request import Request, urlopen

BASE_DIR = Path(__file__).resolve().parent.parent
SOURCES_DIR = BASE_DIR / "sources"
REGISTRY_PATH = SOURCES_DIR / "business-reputation-sources.json"
OUTPUT_PATH = SOURCES_DIR / "business-reputation-evidence.json"

DOMAIN_ALLOWED_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
SIREN_RE = re.compile(r"\b(\d{3}\s?\d{3}\s?\d{3})\b")
COMPANY_LINE_RE = re.compile(r"\*\s+([A-Z0-9][A-Z0-9 .'\-&]+?)\s+-\s+(\d{3}\s?\d{3}\s?\d{3})")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def normalize_siren(raw: object) -> str:
    digits = re.sub(r"\D+", "", str(raw or ""))
    return digits if len(digits) == 9 else ""


def normalize_text(raw: object, max_len: int = 256) -> str:
    value = re.sub(r"\s+", " ", str(raw or "")).strip()
    return value[:max_len]


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


def normalize_phone(raw: object) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    leading_plus = value.startswith("+")
    digits = re.sub(r"\D+", "", value)
    if not digits:
        return ""
    return ("+" if leading_plus else "") + digits


def canonical_company_key(name: object, siren: object) -> str:
    normalized_siren = normalize_siren(siren)
    if normalized_siren:
        return f"siren:{normalized_siren}"
    clean_name = re.sub(r"[^a-z0-9]+", "_", str(name or "").strip().lower()).strip("_")
    return f"name:{clean_name}" if clean_name else ""


def fetch_public_page(url: str, timeout: int = 15) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "CallShieldEvidenceBuilder/1.0 (+evidence-only)",
            "Accept": "text/html, text/plain;q=0.8",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def extract_companies_from_page(text: str, person_key: str, pappers_url: str) -> List[dict]:
    results: List[dict] = []
    seen: Set[str] = set()

    for company_name, siren in COMPANY_LINE_RE.findall(text or ""):
        clean_siren = normalize_siren(siren)
        clean_name = normalize_text(company_name, 160)
        key = canonical_company_key(clean_name, clean_siren)
        if not key or key in seen:
            continue
        seen.add(key)
        results.append(
            {
                "company_key": key,
                "company_name": clean_name,
                "siren": clean_siren,
                "person_key": person_key,
                "role": "pappers_extracted_link",
                "activity_hint": "",
                "domains": [],
                "pappers_url": pappers_url,
                "status": "candidate",
                "source": "pappers_public_page",
            }
        )

    return results


def load_seed_companies(registry: dict) -> List[dict]:
    results: List[dict] = []
    for row in registry.get("known_companies", []):
        if not isinstance(row, dict):
            continue
        siren = normalize_siren(row.get("siren"))
        name = normalize_text(row.get("company_name"), 160)
        key = canonical_company_key(name, siren)
        if not key:
            continue

        domains = []
        seen_domains: Set[str] = set()
        for value in row.get("domains") or []:
            domain = normalize_domain(value)
            if not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)
            domains.append(domain)

        results.append(
            {
                "company_key": key,
                "company_name": name,
                "siren": siren,
                "aliases": [
                    normalize_text(value, 160)
                    for value in row.get("aliases") or []
                    if normalize_text(value, 160)
                ],
                "person_key": normalize_text(row.get("person_key"), 128),
                "role": normalize_text(row.get("role"), 128),
                "activity_hint": normalize_text(row.get("activity_hint"), 256),
                "risk_tags": [
                    normalize_text(value, 96)
                    for value in row.get("risk_tags") or []
                    if normalize_text(value, 96)
                ],
                "candidate_reason": normalize_text(row.get("candidate_reason"), 300),
                "runtime_scoring_allowed": bool(row.get("runtime_scoring_allowed", False)),
                "domains": domains,
                "pappers_url": normalize_text(row.get("pappers_url"), 512),
                "status": normalize_text(row.get("status") or "candidate", 64),
                "source": "curated_registry_seed",
            }
        )
    return results


def merge_companies(rows: Iterable[dict]) -> List[dict]:
    merged: Dict[str, dict] = {}
    for row in rows:
        key = row.get("company_key")
        if not key:
            continue
        current = merged.get(key)
        if current is None:
            merged[key] = dict(row)
            continue

        for field in ("company_name", "siren", "person_key", "role", "activity_hint", "candidate_reason", "pappers_url"):
            if not current.get(field) and row.get(field):
                current[field] = row[field]

        if current.get("status") != "evidence_confirmed" and row.get("status") == "evidence_confirmed":
            current["status"] = "evidence_confirmed"

        domains = list(current.get("domains") or [])
        seen = set(domains)
        for domain in row.get("domains") or []:
            if domain not in seen:
                seen.add(domain)
                domains.append(domain)
        current["domains"] = domains

        risk_tags = list(current.get("risk_tags") or [])
        seen_tags = set(risk_tags)
        for tag in row.get("risk_tags") or []:
            if tag not in seen_tags:
                seen_tags.add(tag)
                risk_tags.append(tag)
        current["risk_tags"] = risk_tags

        aliases = list(current.get("aliases") or [])
        seen_aliases = set(aliases)
        for alias in row.get("aliases") or []:
            if alias not in seen_aliases:
                seen_aliases.add(alias)
                aliases.append(alias)
        current["aliases"] = aliases
        current["runtime_scoring_allowed"] = False

        sources = set(str(current.get("source") or "").split(","))
        sources.add(str(row.get("source") or ""))
        current["source"] = ",".join(sorted(source for source in sources if source))

    return sorted(merged.values(), key=lambda item: (item.get("status") != "evidence_confirmed", item.get("company_name", "")))


def build_evidence_rows(registry: dict) -> List[dict]:
    companies_by_siren = {
        company["siren"]: company
        for company in load_seed_companies(registry)
        if company.get("siren")
    }
    evidence_rows: List[dict] = []

    for source in registry.get("consumer_evidence_sources", []):
        if not isinstance(source, dict):
            continue
        linked_sirens = [normalize_siren(value) for value in source.get("linked_companies") or []]
        linked_sirens = [value for value in linked_sirens if value]
        linked_domains = []
        for value in source.get("linked_domains") or []:
            domain = normalize_domain(value)
            if domain and domain not in linked_domains:
                linked_domains.append(domain)
        linked_roots = []
        for domain in linked_domains:
            root = root_domain(domain)
            if root and root not in linked_roots:
                linked_roots.append(root)

        linked_numbers = []
        for value in source.get("linked_numbers") or []:
            phone = normalize_phone(value)
            if phone and phone not in linked_numbers:
                linked_numbers.append(phone)

        for siren in linked_sirens or [""]:
            company = companies_by_siren.get(siren, {})
            evidence_rows.append(
                {
                    "source_id": normalize_text(source.get("source_id"), 128),
                    "source_name": normalize_text(source.get("source_name"), 128),
                    "source_url": normalize_text(source.get("source_url"), 512),
                    "evidence_type": normalize_text(source.get("evidence_type"), 128),
                    "company_key": canonical_company_key(company.get("company_name"), siren) if siren else "",
                    "company_name": company.get("company_name", ""),
                    "siren": siren,
                    "domains": linked_domains,
                    "root_domains": linked_roots,
                    "phone_numbers": linked_numbers,
                    "observed_patterns": [
                        normalize_text(pattern, 96)
                        for pattern in source.get("observed_patterns") or []
                        if normalize_text(pattern, 96)
                    ],
                    "confidence_score": float(source.get("confidence_score") or 0),
                    "contested": bool(source.get("contested")),
                    "allowed_usage": normalize_text(source.get("allowed_usage"), 128),
                    "notes": normalize_text(source.get("notes"), 500),
                }
            )

    return evidence_rows


def build_payload(fetch: bool = False) -> dict:
    registry = load_json(REGISTRY_PATH, {})
    generated_at = utc_now_iso()

    companies = load_seed_companies(registry)
    fetch_errors: List[dict] = []

    if fetch:
        for seed in registry.get("person_seeds", []):
            if not isinstance(seed, dict):
                continue
            url = str(seed.get("pappers_url") or "").strip()
            person_key = str(seed.get("person_key") or "").strip()
            if not url or not person_key:
                continue
            try:
                html = fetch_public_page(url)
            except (OSError, URLError) as exc:
                fetch_errors.append({"url": url, "error": str(exc)[:240]})
                continue
            companies.extend(extract_companies_from_page(html, person_key, url))

    merged_companies = merge_companies(companies)
    evidence_rows = build_evidence_rows(registry)
    evidence_sirens = {row.get("siren") for row in evidence_rows if row.get("siren")}

    for company in merged_companies:
        if company.get("siren") in evidence_sirens:
            company["status"] = "evidence_confirmed"

    return {
        "schema_version": "business_reputation_evidence_v1",
        "generated_at": generated_at,
        "policy": registry.get("policy", {}),
        "stats": {
            "person_seeds": len(registry.get("person_seeds", [])),
            "companies": len(merged_companies),
            "evidence_rows": len(evidence_rows),
            "fetch_enabled": bool(fetch),
            "fetch_errors": len(fetch_errors),
        },
        "companies": merged_companies,
        "evidence": evidence_rows,
        "fetch_errors": fetch_errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build source-only business reputation evidence for CallShield.")
    parser.add_argument("--fetch", action="store_true", help="Fetch public Pappers pages and add extracted candidate companies.")
    parser.add_argument("--check", action="store_true", help="Validate and print counts without writing output.")
    parser.add_argument("--output", default=str(OUTPUT_PATH), help="Output JSON path.")
    args = parser.parse_args()

    payload = build_payload(fetch=args.fetch)
    if args.check:
        print(json.dumps(payload["stats"], ensure_ascii=False, sort_keys=True))
        return 0

    output_path = Path(args.output)
    write_json(output_path, payload)
    print(f"Wrote {output_path} companies={payload['stats']['companies']} evidence={payload['stats']['evidence_rows']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
