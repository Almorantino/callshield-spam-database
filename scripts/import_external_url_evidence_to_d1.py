#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_FILE = BASE_DIR / "sources" / "url-evidence.json"
SQL_DIR = BASE_DIR / "data" / "external-url-evidence-import"
DB_NAME = "callshield-reports"
SQL_FILE_ROW_CHUNK_SIZE = 1000
SQL_INSERT_ROW_CHUNK_SIZE = 100

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS external_url_evidence_aggregates (
  entity_type TEXT NOT NULL,
  entity_value TEXT NOT NULL,
  root_domain TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT 'unknown',
  phishing_count INTEGER NOT NULL DEFAULT 0,
  malware_count INTEGER NOT NULL DEFAULT 0,
  smishing_count INTEGER NOT NULL DEFAULT 0,
  official_ioc_count INTEGER NOT NULL DEFAULT 0,
  source_count INTEGER NOT NULL DEFAULT 0,
  evidence_count INTEGER NOT NULL DEFAULT 0,
  url_count INTEGER NOT NULL DEFAULT 0,
  fresh_count INTEGER NOT NULL DEFAULT 0,
  aging_count INTEGER NOT NULL DEFAULT 0,
  stale_count INTEGER NOT NULL DEFAULT 0,
  unknown_freshness_count INTEGER NOT NULL DEFAULT 0,
  max_confidence REAL NOT NULL DEFAULT 0,
  confidence_sum REAL NOT NULL DEFAULT 0,
  sources_json TEXT NOT NULL DEFAULT '[]',
  first_seen TEXT,
  last_seen TEXT,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY(entity_type, entity_value)
);
CREATE INDEX IF NOT EXISTS idx_external_url_evidence_root ON external_url_evidence_aggregates(root_domain);
CREATE INDEX IF NOT EXISTS idx_external_url_evidence_category ON external_url_evidence_aggregates(category);
CREATE INDEX IF NOT EXISTS idx_external_url_evidence_updated_at ON external_url_evidence_aggregates(updated_at);
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


def normalize_category(value: object) -> str:
  category = str(value or "").strip().lower()
  if category in {"phishing_url", "malware_url", "smishing_report", "official_ioc"}:
    return category
  return "unknown"


def category_columns(category: str) -> Dict[str, int]:
  return {
    "phishing_url": 1 if category == "phishing_url" else 0,
    "malware_url": 1 if category == "malware_url" else 0,
    "smishing_report": 1 if category == "smishing_report" else 0,
    "official_ioc": 1 if category == "official_ioc" else 0,
  }


def primary_category(counts: Dict[str, int]) -> str:
  ordered = ["official_ioc", "malware_url", "phishing_url", "smishing_report", "unknown"]
  best = "unknown"
  best_count = -1
  for category in ordered:
    count = int(counts.get(category, 0))
    if count > best_count:
      best = category
      best_count = count
  return best


def min_seen(current: Optional[str], incoming: object) -> Optional[str]:
  value = str(incoming or "").strip()
  if not value:
    return current
  if not current:
    return value
  return min(current, value)


def max_seen(current: Optional[str], incoming: object) -> Optional[str]:
  value = str(incoming or "").strip()
  if not value:
    return current
  if not current:
    return value
  return max(current, value)


def empty_aggregate(entity_type: str, entity_value: str, root_domain: str) -> dict:
  return {
    "entity_type": entity_type,
    "entity_value": entity_value,
    "root_domain": root_domain,
    "counts": {
      "phishing_url": 0,
      "malware_url": 0,
      "smishing_report": 0,
      "official_ioc": 0,
      "unknown": 0,
    },
    "evidence_count": 0,
    "url_count": 0,
    "fresh_count": 0,
    "aging_count": 0,
    "stale_count": 0,
    "unknown_freshness_count": 0,
    "max_confidence": 0.0,
    "confidence_sum": 0.0,
    "sources": set(),
    "first_seen": None,
    "last_seen": None,
  }


def add_evidence(aggregates: Dict[tuple, dict], entity_type: str, entity_value: str, root_domain: str, row: dict, is_url: bool = False) -> None:
  if not entity_value:
    return

  key = (entity_type, entity_value)
  aggregate = aggregates.setdefault(key, empty_aggregate(entity_type, entity_value, root_domain))
  category = normalize_category(row.get("category"))
  aggregate["counts"][category] = int(aggregate["counts"].get(category, 0)) + 1
  aggregate["evidence_count"] += max(1, int(row.get("evidence_count") or 1))
  aggregate["url_count"] += 1 if is_url else 0

  freshness = str(row.get("freshness") or "unknown").strip().lower()
  if freshness == "fresh":
    aggregate["fresh_count"] += 1
  elif freshness == "aging":
    aggregate["aging_count"] += 1
  elif freshness == "stale":
    aggregate["stale_count"] += 1
  else:
    aggregate["unknown_freshness_count"] += 1

  confidence = float(row.get("confidence") or 0.0)
  aggregate["max_confidence"] = max(float(aggregate["max_confidence"]), confidence)
  aggregate["confidence_sum"] += confidence
  aggregate["sources"].update(str(source) for source in row.get("sources", []) if str(source).strip())
  aggregate["first_seen"] = min_seen(aggregate["first_seen"], row.get("first_seen"))
  aggregate["last_seen"] = max_seen(aggregate["last_seen"], row.get("last_seen"))


def load_aggregates() -> Dict[tuple, dict]:
  payload = json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
  aggregates: Dict[tuple, dict] = {}

  for row in payload.get("domains", []):
    domain = str(row.get("domain") or "").strip().lower()
    root = str(row.get("root_domain") or "").strip().lower()
    if not domain or not root:
      continue
    add_evidence(aggregates, "domain", domain, root, row, is_url=False)
    add_evidence(aggregates, "root_domain", root, root, row, is_url=False)

  for row in payload.get("urls", []):
    domain = str(row.get("domain") or "").strip().lower()
    root = str(row.get("root_domain") or "").strip().lower()
    if not domain or not root:
      continue
    add_evidence(aggregates, "domain", domain, root, row, is_url=True)
    add_evidence(aggregates, "root_domain", root, root, row, is_url=True)

  return aggregates


def row_to_sql_tuple(row: dict) -> str:
  counts = row["counts"]
  sources_json = json.dumps(sorted(row["sources"]), separators=(",", ":"))
  category = primary_category(counts)
  return (
    "('{}','{}','{}','{}',{},{},{},{},{},{},{},{},{},{},{},{:.4f},{:.4f},'{}',{}, {}, unixepoch())"
  ).format(
    sql_escape(row["entity_type"]),
    sql_escape(row["entity_value"]),
    sql_escape(row["root_domain"]),
    sql_escape(category),
    int(counts.get("phishing_url", 0)),
    int(counts.get("malware_url", 0)),
    int(counts.get("smishing_report", 0)),
    int(counts.get("official_ioc", 0)),
    len(row["sources"]),
    int(row["evidence_count"]),
    int(row["url_count"]),
    int(row["fresh_count"]),
    int(row["aging_count"]),
    int(row["stale_count"]),
    int(row["unknown_freshness_count"]),
    float(row["max_confidence"]),
    float(row["confidence_sum"]),
    sql_escape(sources_json),
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
  schema_path = SQL_DIR / "external-url-evidence-schema.sql"
  schema_path.write_text(SCHEMA_SQL + "\n", encoding="utf-8")
  paths.append(schema_path)

  columns = (
    "entity_type, entity_value, root_domain, category, phishing_count, malware_count, "
    "smishing_count, official_ioc_count, source_count, evidence_count, url_count, "
    "fresh_count, aging_count, stale_count, unknown_freshness_count, max_confidence, "
    "confidence_sum, sources_json, first_seen, last_seen, updated_at"
  )

  for index, batch in enumerate(chunked(rows, SQL_FILE_ROW_CHUNK_SIZE), start=1):
    path = SQL_DIR / f"external-url-evidence-import-part-{index}.sql"
    with path.open("w", encoding="utf-8") as f:
      for insert_batch in chunked(batch, SQL_INSERT_ROW_CHUNK_SIZE):
        f.write(f"INSERT OR REPLACE INTO external_url_evidence_aggregates ({columns}) VALUES\n")
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
    "domain_rows": sum(1 for row in rows if row["entity_type"] == "domain"),
    "root_rows": sum(1 for row in rows if row["entity_type"] == "root_domain"),
    "phishing_rows": sum(1 for row in rows if primary_category(row["counts"]) == "phishing_url"),
    "smishing_rows": sum(1 for row in rows if primary_category(row["counts"]) == "smishing_report"),
  }


def main() -> None:
  parser = argparse.ArgumentParser(description="Import compact external URL evidence aggregates into D1.")
  parser.add_argument("--write-sql", action="store_true", help="Write SQL chunk files under data/external-url-evidence-import.")
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
