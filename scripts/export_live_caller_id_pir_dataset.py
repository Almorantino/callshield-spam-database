#!/usr/bin/env python3

import argparse
import csv
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = BASE_DIR / "data" / "live-lookup-export.csv"
DEFAULT_OUTPUT_DIR = BASE_DIR / "data" / "live-caller-id-pir"
DEFAULT_CONSTRUCT_DATABASE = (
    BASE_DIR
    / "CallShieldLiveCallerIDPIRService"
    / ".build"
    / "release"
    / "ConstructDatabase"
)

APPLE_TEST_NUMBER = "+14085551212"
APPLE_TEST_NAME = "Johnny Appleseed"
DEFAULT_CACHE_EXPIRY_MINUTES = 24 * 60

BLOCK_CATEGORIES = {
    "fraud",
    "scam",
    "spam",
    "telemarketing",
    "demarchage",
    "démarchage",
}

SAFE_CATEGORIES = {"safe", "allow", "trusted"}


def normalize_phone_number(value: str) -> Optional[str]:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if not digits:
        return None
    return f"+{digits}"


def textproto_escape(value: str) -> str:
    return (
        str(value or "")
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def identity_category_for(category: str, *, apple_test_identity: bool = False) -> str:
    if apple_test_identity:
        return "IDENTITY_CATEGORY_PERSON"
    if category.strip().lower() in SAFE_CATEGORIES:
        return "IDENTITY_CATEGORY_PERSON"
    return "IDENTITY_CATEGORY_BUSINESS"


def should_block(category: str, risk_level: int) -> bool:
    normalized = category.strip().lower()
    if normalized in SAFE_CATEGORIES:
        return False
    return normalized in BLOCK_CATEGORIES and risk_level >= 70


def read_live_lookup_rows(input_file: Path, limit: Optional[int]) -> list[dict]:
    rows = []
    seen = set()

    with input_file.open("r", encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        for row in reader:
            number = normalize_phone_number(row.get("number_e164", ""))
            if not number or number in seen:
                continue

            category = str(row.get("category") or "unknown").strip().lower()
            try:
                risk_level = int(float(row.get("risk_level") or 0))
            except ValueError:
                risk_level = 0

            label = str(row.get("label") or "").strip() or "CallShield"
            seen.add(number)
            rows.append(
                {
                    "number": number,
                    "name": label,
                    "category": category,
                    "risk_level": risk_level,
                    "block": should_block(category, risk_level),
                    "identity_category": identity_category_for(category),
                }
            )

            if limit is not None and len(rows) >= limit:
                break

    rows_by_number = {row["number"]: row for row in rows}
    rows_by_number[APPLE_TEST_NUMBER] = {
        "number": APPLE_TEST_NUMBER,
        "name": APPLE_TEST_NAME,
        "category": "apple_test",
        "risk_level": 0,
        "block": False,
        "identity_category": identity_category_for(
            "apple_test",
            apple_test_identity=True,
        ),
    }
    return [rows_by_number[number] for number in sorted(rows_by_number)]


def write_input_textproto(rows: list[dict], output_file: Path, cache_expiry_minutes: int):
    with output_file.open("w", encoding="utf-8") as destination:
        for row in rows:
            destination.write("identities {\n")
            destination.write(f'  key: "{textproto_escape(row["number"])}"\n')
            destination.write("  value {\n")
            destination.write(f'    name: "{textproto_escape(row["name"])}"\n')
            destination.write(f"    cache_expiry_minutes: {cache_expiry_minutes}\n")
            destination.write(f"    block: {str(row['block']).lower()}\n")
            destination.write(f"    category: {row['identity_category']}\n")
            destination.write("  }\n")
            destination.write("}\n")


def write_summary(rows: list[dict], output_file: Path, input_file: Path):
    categories = Counter(row["category"] for row in rows)
    payload = {
        "source": str(input_file),
        "total_identities": len(rows),
        "blocked_identities": sum(1 for row in rows if row["block"]),
        "allowed_identities": sum(1 for row in rows if not row["block"]),
        "apple_test_identity": APPLE_TEST_NUMBER,
        "categories": dict(sorted(categories.items())),
    }
    output_file.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def run_construct_database(binary: Path, input_file: Path, block_file: Path, identity_file: Path):
    if not binary.exists():
        raise FileNotFoundError(
            f"ConstructDatabase not found at {binary}. "
            "Build it with: swift build -c release --product ConstructDatabase"
        )

    subprocess.run(
        [str(binary), str(input_file), str(block_file), str(identity_file)],
        check=True,
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Export CallShield live_lookup data to Apple Live Caller ID PIR input files."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--construct-database", type=Path, default=DEFAULT_CONSTRUCT_DATABASE)
    parser.add_argument("--cache-expiry-minutes", type=int, default=DEFAULT_CACHE_EXPIRY_MINUTES)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--skip-binary", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.input.exists():
        raise FileNotFoundError(f"Input CSV not found: {args.input}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    input_textproto = args.output_dir / "input.txtpb"
    block_file = args.output_dir / "block.binpb"
    identity_file = args.output_dir / "identity.binpb"
    summary_file = args.output_dir / "summary.json"

    rows = read_live_lookup_rows(args.input, args.limit)
    write_input_textproto(rows, input_textproto, args.cache_expiry_minutes)
    write_summary(rows, summary_file, args.input)

    if not args.skip_binary:
        run_construct_database(args.construct_database, input_textproto, block_file, identity_file)

    print(f"✅ Exported {len(rows)} Live Caller ID identities")
    print(f"→ input: {input_textproto}")
    if not args.skip_binary:
        print(f"→ block: {block_file}")
        print(f"→ identity: {identity_file}")
    print(f"→ summary: {summary_file}")


if __name__ == "__main__":
    main()
