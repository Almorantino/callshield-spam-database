#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_FILE = BASE_DIR / "sources" / "business-reputation-evidence.json"
SQL_DIR = BASE_DIR / "data" / "business-reputation-import"
DB_NAME = "callshield-reports"
SQL_FILE_ROW_CHUNK_SIZE = 500
SQL_INSERT_ROW_CHUNK_SIZE = 100

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS business_reputation_evidence_aggregates (
  entity_type TEXT NOT NULL,
  entity_value TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'candidate',
  company_keys_json TEXT NOT NULL DEFAULT '[]',
  company_names_json TEXT NOT NULL DEFAULT '[]',
  sirens_json TEXT NOT NULL DEFAULT '[]',
  domains_json TEXT NOT NULL DEFAULT '[]',
  phone_numbers_json TEXT NOT NULL DEFAULT '[]',
  risk_tags_json TEXT NOT NULL DEFAULT '[]',
  observed_patterns_json TEXT NOT NULL DEFAULT '[]',
  source_count INTEGER NOT NULL DEFAULT 0,
  corporate_source_count INTEGER NOT NULL DEFAULT 0,
  consumer_evidence_count INTEGER NOT NULL DEFAULT 0,
  contested_evidence_count INTEGER NOT NULL DEFAULT 0,
  max_confidence REAL NOT NULL DEFAULT 0,
  confidence_sum REAL NOT NULL DEFAULT 0,
  sources_json TEXT NOT NULL DEFAULT '[]',
  first_seen TEXT,
  last_seen TEXT,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY(entity_type, entity_value)
);
CREATE INDEX IF NOT EXISTS idx_business_reputation_status ON business_reputation_evidence_aggregates(status);
CREATE INDEX IF NOT EXISTS idx_business_reputation_updated_at ON business_reputation_evidence_aggregates(updated_at);
CREATE INDEX IF NOT EXISTS idx_business_reputation_entity ON business_reputation_evidence_aggregates(entity_type, entity_value);
""".strip()


def sql_escape(value: object) -> str:
  return str(value or "").replace("'", "''")


def run(command: List[str]) -> str:
  result = subprocess.run(command, cwd=BASE_DIR, capture_output=True, text=True)
  if result.returncode != 0:
    if result.stdout:
      print(result.stdout)
    if result.stderr:
      print(result.stderr)
    raise RuntimeError(f"Command failed: {' '.join(command)}")
  return result.stdout


def as_clean_list(value: object) -> List[str]:
  if not isinstance(value, list):
    return []
  results: List[str] = []
  seen: Set[str] = set()
  for item in value:
    text = str(item or "").strip()
    if not text or text in seen:
      continue
    seen.add(text)
    results.append(text)
  return results


def normalize_status(value: object, has_consumer_evidence: bool = False) -> str:
  status = str(value or "").strip().lower()
  if has_consumer_evidence or status == "evidence_confirmed":
    return "evidence_confirmed"
  if status == "rejected":
    return "rejected"
  return "candidate"


def empty_aggregate(entity_type: str, entity_value: str) -> dict:
  return {
    "entity_type": entity_type,
    "entity_value": entity_value,
    "status": "candidate",
    "company_keys": set(),
    "company_names": set(),
    "sirens": set(),
    "domains": set(),
    "phone_numbers": set(),
    "risk_tags": set(),
    "observed_patterns": set(),
    "sources": set(),
    "corporate_source_count": 0,
    "consumer_evidence_count": 0,
    "contested_evidence_count": 0,
    "max_confidence": 0.0,
    "confidence_sum": 0.0,
    "first_seen": None,
    "last_seen": None,
  }


def add_seen(row: dict, generated_at: str) -> None:
  if not row.get("first_seen"):
    row["first_seen"] = generated_at
  row["last_seen"] = generated_at


def add_company_context(row: dict, company: dict) -> None:
  for field, target in (
    ("company_key", "company_keys"),
    ("company_name", "company_names"),
    ("siren", "sirens"),
  ):
    value = str(company.get(field) or "").strip()
    if value:
      row[target].add(value)
  row["domains"].update(as_clean_list(company.get("domains")))
  row["risk_tags"].update(as_clean_list(company.get("risk_tags")))


def add_company_candidate(aggregates: Dict[tuple, dict], company: dict, generated_at: str) -> None:
  company_key = str(company.get("company_key") or "").strip()
  if not company_key:
    return
  key = ("company", company_key)
  row = aggregates.setdefault(key, empty_aggregate(*key))
  add_company_context(row, company)
  source = str(company.get("source") or "pappers_public_registry").strip()
  if source:
    row["sources"].add(source)
  row["corporate_source_count"] += 1
  row["status"] = normalize_status(company.get("status"), row["consumer_evidence_count"] > 0)
  add_seen(row, generated_at)


def add_consumer_evidence(
  aggregates: Dict[tuple, dict],
  entity_type: str,
  entity_value: str,
  evidence: dict,
  company: Optional[dict],
  generated_at: str,
) -> None:
  clean_value = str(entity_value or "").strip()
  if not clean_value:
    return

  key = (entity_type, clean_value)
  row = aggregates.setdefault(key, empty_aggregate(*key))
  if company:
    add_company_context(row, company)

  source_id = str(evidence.get("source_id") or evidence.get("source_name") or "").strip()
  if source_id:
    row["sources"].add(source_id)
  row["consumer_evidence_count"] += 1
  if evidence.get("contested"):
    row["contested_evidence_count"] += 1
  confidence = float(evidence.get("confidence_score") or 0.0)
  row["max_confidence"] = max(float(row["max_confidence"]), confidence)
  row["confidence_sum"] += confidence
  row["observed_patterns"].update(as_clean_list(evidence.get("observed_patterns")))
  row["domains"].update(as_clean_list(evidence.get("domains")))
  row["phone_numbers"].update(as_clean_list(evidence.get("phone_numbers")))
  row["status"] = "evidence_confirmed"
  add_seen(row, generated_at)


def load_aggregates() -> Dict[tuple, dict]:
  payload = json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
  generated_at = str(payload.get("generated_at") or "").strip()
  aggregates: Dict[tuple, dict] = {}
  companies_by_key: Dict[str, dict] = {}
  companies_by_siren: Dict[str, dict] = {}

  for company in payload.get("companies", []):
    if not isinstance(company, dict):
      continue
    company_key = str(company.get("company_key") or "").strip()
    siren = str(company.get("siren") or "").strip()
    if company_key:
      companies_by_key[company_key] = company
    if siren:
      companies_by_siren[siren] = company
    add_company_candidate(aggregates, company, generated_at)

  for evidence in payload.get("evidence", []):
    if not isinstance(evidence, dict):
      continue
    company = companies_by_key.get(str(evidence.get("company_key") or "").strip())
    if not company:
      company = companies_by_siren.get(str(evidence.get("siren") or "").strip())
    company_key = str(evidence.get("company_key") or "").strip()
    if company_key:
      add_consumer_evidence(aggregates, "company", company_key, evidence, company, generated_at)
    for domain in as_clean_list(evidence.get("domains")):
      add_consumer_evidence(aggregates, "domain", domain, evidence, company, generated_at)
    for root_domain in as_clean_list(evidence.get("root_domains")):
      add_consumer_evidence(aggregates, "root_domain", root_domain, evidence, company, generated_at)
    for phone_number in as_clean_list(evidence.get("phone_numbers")):
      add_consumer_evidence(aggregates, "phone_number", phone_number, evidence, company, generated_at)

  return aggregates


def json_array(values: Iterable[str]) -> str:
  return json.dumps(sorted(str(value) for value in values if str(value).strip()), ensure_ascii=False, separators=(",", ":"))


def row_to_sql_tuple(row: dict) -> str:
  source_count = len(row["sources"])
  return (
    "('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}',{},{},{},{},{:.4f},{:.4f},'{}',{}, {}, unixepoch())"
  ).format(
    sql_escape(row["entity_type"]),
    sql_escape(row["entity_value"]),
    sql_escape(normalize_status(row["status"], row["consumer_evidence_count"] > 0)),
    sql_escape(json_array(row["company_keys"])),
    sql_escape(json_array(row["company_names"])),
    sql_escape(json_array(row["sirens"])),
    sql_escape(json_array(row["domains"])),
    sql_escape(json_array(row["phone_numbers"])),
    sql_escape(json_array(row["risk_tags"])),
    sql_escape(json_array(row["observed_patterns"])),
    source_count,
    int(row["corporate_source_count"]),
    int(row["consumer_evidence_count"]),
    int(row["contested_evidence_count"]),
    float(row["max_confidence"]),
    float(row["confidence_sum"]),
    sql_escape(json_array(row["sources"])),
    f"'{sql_escape(row['first_seen'])}'" if row.get("first_seen") else "NULL",
    f"'{sql_escape(row['last_seen'])}'" if row.get("last_seen") else "NULL",
  )


def chunked(items: Iterable[dict], size: int):
  batch = []
  for item in items:
    batch.append(item)
    if len(batch) >= size:
      yield batch
      batch = []
  if batch:
    yield batch


def reset_sql_dir() -> None:
  if SQL_DIR.exists():
    shutil.rmtree(SQL_DIR)
  SQL_DIR.mkdir(parents=True, exist_ok=True)


def write_sql_chunks(rows: List[dict]) -> List[Path]:
  reset_sql_dir()
  paths: List[Path] = []
  schema_path = SQL_DIR / "business-reputation-schema.sql"
  schema_path.write_text(SCHEMA_SQL + "\n", encoding="utf-8")
  paths.append(schema_path)

  columns = (
    "entity_type, entity_value, status, company_keys_json, company_names_json, "
    "sirens_json, domains_json, phone_numbers_json, risk_tags_json, observed_patterns_json, "
    "source_count, corporate_source_count, consumer_evidence_count, contested_evidence_count, "
    "max_confidence, confidence_sum, sources_json, first_seen, last_seen, updated_at"
  )

  for index, batch in enumerate(chunked(rows, SQL_FILE_ROW_CHUNK_SIZE), start=1):
    path = SQL_DIR / f"business-reputation-import-part-{index}.sql"
    with path.open("w", encoding="utf-8") as f:
      for insert_batch in chunked(batch, SQL_INSERT_ROW_CHUNK_SIZE):
        f.write(f"INSERT OR REPLACE INTO business_reputation_evidence_aggregates ({columns}) VALUES\n")
        f.write(",\n".join(row_to_sql_tuple(row) for row in insert_batch))
        f.write(";\n")
    paths.append(path)

  return paths


def import_sql_files(paths: List[Path]) -> None:
  for index, path in enumerate(paths, start=1):
    run(["wrangler", "d1", "execute", DB_NAME, "--remote", "--file", str(path), "--yes"])
    print(f"imported {index}/{len(paths)} {path.name}")


def summarize(rows: List[dict]) -> dict:
  return {
    "rows": len(rows),
    "company_rows": sum(1 for row in rows if row["entity_type"] == "company"),
    "domain_rows": sum(1 for row in rows if row["entity_type"] == "domain"),
    "root_domain_rows": sum(1 for row in rows if row["entity_type"] == "root_domain"),
    "phone_number_rows": sum(1 for row in rows if row["entity_type"] == "phone_number"),
    "evidence_confirmed_rows": sum(1 for row in rows if row["consumer_evidence_count"] > 0),
    "candidate_rows": sum(1 for row in rows if row["consumer_evidence_count"] == 0),
    "consumer_evidence_count": sum(int(row["consumer_evidence_count"]) for row in rows),
  }


def main() -> None:
  parser = argparse.ArgumentParser(description="Import business reputation evidence aggregates into D1.")
  parser.add_argument("--write-sql", action="store_true", help="Write SQL chunk files under data/business-reputation-import.")
  parser.add_argument("--execute", action="store_true", help="Execute generated SQL chunks against remote D1.")
  args = parser.parse_args()

  if not EVIDENCE_FILE.exists():
    raise FileNotFoundError(f"Missing evidence file: {EVIDENCE_FILE}")

  aggregates = load_aggregates()
  rows = sorted(aggregates.values(), key=lambda row: (row["entity_type"], row["entity_value"]))
  summary = summarize(rows)
  print(json.dumps(summary, ensure_ascii=False, indent=2))

  if not args.write_sql and not args.execute:
    print("dry_run=true")
    return

  paths = write_sql_chunks(rows)
  print(f"sql_chunks={len(paths)}")
  print(f"sql_dir={SQL_DIR}")

  if args.execute:
    import_sql_files(paths)


if __name__ == "__main__":
  main()
