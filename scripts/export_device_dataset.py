import json
import csv
import sqlite3
from pathlib import Path
from datetime import datetime

from db import get_connection, now

BASE_DIR = Path(__file__).resolve().parent.parent
STATE_FILE = BASE_DIR / "data" / "device-state.json"
OUTPUT_FILE = BASE_DIR / "data" / "device-database.json"
LIVE_LOOKUP_FILE = BASE_DIR / "data" / "live-lookup-export.csv"
SMS_FILTER_FILE = BASE_DIR / "data" / "sms-filter.sqlite"

MAX_CALLKIT_BLOCKS = 50_000
MAX_IDENTIFIES = 20_000

# Production fetch limit for block rows
BLOCK_FETCH_LIMIT = 250_000

# TEMP TEST CAP (for CallKit activation debugging only)
TEST_BLOCK_LIMIT = None  # production mode (no artificial cap)

LIVE_LOOKUP_PREFIX_SUPPLEMENT_MIN_COUNT = 1000
LIVE_LOOKUP_PREFIX_SUPPLEMENT_PER_PREFIX_LIMIT = 1000
OFFICIAL_TELEMARKETING_PREFIXES = (
    "33162",
    "33163",
    "33270",
    "33271",
    "33377",
    "33378",
    "33424",
    "33425",
    "33568",
    "33569",
    "33948",
    "33949",
    "339475",
    "339476",
    "339477",
    "339478",
    "339479",
)


# ------------------------------------------------------------
# helpers
# ------------------------------------------------------------


def parse_sources(value):
    if not value:
        return []

    if isinstance(value, list):
        return value

    text = str(value).strip()
    if not text:
        return []

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
    except Exception:
        pass

    return [text]


def normalize_callkit_number(value):
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if not digits:
        return None

    if digits.startswith("33"):
        if len(digits) == 11:
            return digits
        return None

    if digits.startswith("0") and len(digits) == 10:
        return "33" + digits[1:]

    return None


def is_official_telemarketing_number(value):
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if not digits:
        return False
    if digits.startswith("0"):
        normalized = "33" + digits[1:]
    elif digits.startswith("33"):
        normalized = digits
    else:
        normalized = normalize_callkit_number(digits) or digits
    return any(normalized.startswith(prefix) for prefix in OFFICIAL_TELEMARKETING_PREFIXES)


def raw_numbers_columns(conn):
    rows = conn.execute("PRAGMA table_info(raw_numbers)").fetchall()
    return {str(row[1]) for row in rows}



def feedback_select_fields(alias, columns):
    optional_feedback_fields = {
        "safe_reports": f"0 AS safe_reports",
        "fraud_reports": f"0 AS fraud_reports",
        "telemarketing_reports": f"0 AS telemarketing_reports",
    }

    select_feedback_fields = []
    for field, fallback in optional_feedback_fields.items():
        if field in columns:
            select_feedback_fields.append(f"{alias}.{field}")
        else:
            select_feedback_fields.append(fallback)

    return ", ".join(select_feedback_fields)


# ------------------------------------------------------------
# live lookup export helpers
# ------------------------------------------------------------

def live_lookup_category_for_row(row):
    category = str(row["category"] or "").strip().lower()
    action = str(row["action"] or "").strip().lower()

    if category in {"fraud", "scam", "spam", "telemarketing", "demarchage", "démarchage", "safe"}:
        return category

    if category == "unknown" and action in {"block", "identify"} and is_official_telemarketing_number(row["number"]):
        return "telemarketing"

    return category


def live_lookup_label_for_row(row):
    category = live_lookup_category_for_row(row)
    score = int(row["score"] or 0)

    if category in {"fraud", "scam"}:
        return "Fraude probable", "fraud", max(0.90, min(0.99, score / 100.0)), 95

    if category in {"telemarketing", "demarchage", "démarchage"}:
        return "Démarchage probable", "telemarketing", max(0.75, min(0.95, score / 100.0)), 80

    if category == "spam":
        return "Spam probable", "spam", max(0.80, min(0.97, score / 100.0)), 85

    if category == "safe":
        return "Numéro fiable", "safe", 0.99, 10

    return None, None, 0.0, 0


def fetch_live_lookup_rows(conn, limit: int):
    columns = raw_numbers_columns(conn)
    select_feedback_fields = feedback_select_fields("r", columns)

    query = f"""
        SELECT
            s.number,
            s.score,
            s.action,
            s.label,
            s.category,
            s.reports,
            {select_feedback_fields},
            s.source_confidence,
            s.last_seen,
            r.source,
            r.source_detail,
            r.prefix_official,
            r.scam_flag
        FROM scored_numbers s
        LEFT JOIN raw_numbers r ON r.number = s.number
        WHERE s.action IN ('block', 'identify')
          AND s.category IN ('fraud', 'scam', 'spam', 'telemarketing', 'demarchage', 'démarchage', 'safe')
        ORDER BY
            fraud_reports DESC,
            telemarketing_reports DESC,
            safe_reports ASC,
            CASE WHEN s.category IN ('fraud', 'scam') THEN 1 ELSE 0 END DESC,
            r.scam_flag DESC,
            r.prefix_official DESC,
            s.source_confidence DESC,
            s.reports DESC,
            s.score DESC,
            s.last_seen DESC
        LIMIT ?
    """

    return conn.execute(query, (limit,))


def fetch_official_telemarketing_cluster_prefixes(conn):
    try:
        rows = conn.execute(
            """
            SELECT prefix7, count
            FROM cluster_candidates
            WHERE count >= ?
            ORDER BY count DESC, prefix7 ASC
            """,
            (LIVE_LOOKUP_PREFIX_SUPPLEMENT_MIN_COUNT,),
        ).fetchall()
    except Exception:
        return []

    prefixes = []
    for row in rows:
        prefix = str(row["prefix7"] or "").strip()
        if prefix and is_official_telemarketing_number(prefix):
            prefixes.append(prefix)
    return prefixes


def fetch_official_telemarketing_prefix_rows(conn):
    columns = raw_numbers_columns(conn)
    select_feedback_fields = feedback_select_fields("r", columns)
    prefixes = fetch_official_telemarketing_cluster_prefixes(conn)
    rows = []

    for prefix in prefixes:
        query = f"""
            SELECT
                s.number,
                s.score,
                s.action,
                s.label,
                s.category,
                s.reports,
                {select_feedback_fields},
                s.source_confidence,
                s.last_seen,
                r.source,
                r.source_detail,
                r.prefix_official,
                r.scam_flag
            FROM scored_numbers s
            LEFT JOIN raw_numbers r ON r.number = s.number
            WHERE s.action IN ('block', 'identify')
              AND COALESCE(s.category, 'unknown') = 'unknown'
              AND s.number LIKE ?
            ORDER BY
                s.score DESC,
                s.number ASC
            LIMIT ?
        """
        rows.extend(
            conn.execute(
                query,
                (f"{prefix}%", LIVE_LOOKUP_PREFIX_SUPPLEMENT_PER_PREFIX_LIMIT),
            ).fetchall()
        )

    return rows


def build_live_lookup_export(conn, limit: int = 250_000):
    rows = list(fetch_live_lookup_rows(conn, limit))
    rows.extend(fetch_official_telemarketing_prefix_rows(conn))
    items = []
    seen = set()

    for row in rows:
        normalized = normalize_callkit_number(row["number"])
        if not normalized:
            continue
        if normalized in seen:
            continue

        label, category, confidence, risk_level = live_lookup_label_for_row(row)
        if not label or not category:
            continue

        seen.add(normalized)
        stable_updated_at = iso_from_row(row["last_seen"]) or ""
        items.append(
            {
                "number_e164": normalized,
                "label": label,
                "category": category,
                "confidence": round(float(confidence), 4),
                "risk_level": int(risk_level),
                "source": "pipeline_v2",
                "updated_at": stable_updated_at,
            }
        )

    items.sort(key=lambda item: item["number_e164"])
    return items


# ------------------------------------------------------------
# incremental helpers
# ------------------------------------------------------------

def parse_generated_at(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


def iso_from_row(value):
    text = str(value or "").strip()
    return text or None


def fetch_recent_scored_rows(conn, since_iso: str):
    query = """
        SELECT
            number,
            score,
            action,
            label,
            category,
            reports,
            source_confidence,
            last_seen,
            scored_at
        FROM scored_numbers
        WHERE scored_at > ?
    """
    return conn.execute(query, (since_iso,)).fetchall()


# ------------------------------------------------------------
# unchanged early-exit incremental helper
# ------------------------------------------------------------

def build_unchanged_device_dataset(previous_state):
    device = dict(previous_state)
    new_version = int(previous_state.get("version", 1)) + 1
    device["version"] = new_version
    device["generated_at"] = now() + "_v" + str(new_version)
    device["incremental_mode"] = True
    device["incremental_reason"] = "no_recent_scored_rows"
    device["delta"] = {
        "added_blocks": 0,
        "removed_blocks": 0,
        "added_identify": 0,
        "removed_identify": 0,
    }
    return device



def build_sms_filter_numbers(device):
    # SMS-specific selection (V2+): focus on FR mobile ranges and cap size
    MAX_SMS_NUMBERS = 200_000

    candidates = []
    for n in device.get("blocked_numbers", []):
        s = str(n)
        if not s.isdigit():
            continue
        # Focus on French mobile numbers (E.164 without +): 336 / 337
        if s.startswith("336") or s.startswith("337"):
            candidates.append(int(s))

    # Deduplicate and keep deterministic order
    candidates = sorted(set(candidates))

    # Cap for extension performance
    if len(candidates) > MAX_SMS_NUMBERS:
        candidates = candidates[:MAX_SMS_NUMBERS]

    return candidates


def write_sms_filter_sqlite(db_path, version, generated_at, numbers):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("CREATE TABLE blocked_numbers (number INTEGER PRIMARY KEY)")
        conn.executemany(
            "INSERT OR IGNORE INTO blocked_numbers(number) VALUES (?)",
            ((int(number),) for number in numbers),
        )
        conn.executemany(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            [
                ("version", str(int(version))),
                ("generated_at", str(generated_at)),
                ("numbers_count", str(len(numbers))),
            ],
        )
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------
# priority helpers
# ------------------------------------------------------------


def block_priority(row):
    sources = parse_sources(row["source"])
    category = str(row["category"] or "")
    reports = int(row["reports"] or 0)
    source_confidence = float(row["source_confidence"] or 0)
    score = int(row["score"] or 0)
    last_seen = str(row["last_seen"] or "")
    source_detail = str(row["source_detail"] or "")
    prefix_official = int(row["prefix_official"] or 0)
    scam_flag = int(row["scam_flag"] or 0)

    safe_reports = int(row["safe_reports"] or 0)
    fraud_reports = int(row["fraud_reports"] or 0)
    telemarketing_reports = int(row["telemarketing_reports"] or 0)

    community_live = 1 if "community_live" in sources else 0
    community_reports = 1 if "community-reports" in sources else 0
    public_dataset = 1 if "public-dataset" in sources else 0
    official = 1 if "official" in sources else 0
    generated_campaigns = 1 if "generated_campaigns" in sources else 0
    fraud_like = 1 if category in {"fraud", "scam"} else 0
    multi_source = len(set(sources))
    generated_massive = 1 if "cluster-prefix6-massive:" in source_detail else 0
    generated_prefix7 = 1 if "cluster-prefix7:" in source_detail else 0

    real_observed = 0 if generated_campaigns else 1
    generated_penalty = 0 if not generated_campaigns else -1
    generated_massive_penalty = 0 if not generated_massive else -1
    generated_prefix7_penalty = 0 if not generated_prefix7 else -1

    return (
        real_observed,
        fraud_reports,
        telemarketing_reports,
        -safe_reports,
        community_live,
        community_reports,
        public_dataset,
        official,
        multi_source,
        fraud_like,
        scam_flag,
        prefix_official,
        source_confidence,
        reports,
        score,
        last_seen,
        generated_penalty,
        generated_massive_penalty,
        generated_prefix7_penalty,
    )


def is_generated(row):
    sources = parse_sources(row["source"])
    return 1 if "generated_campaigns" in sources else 0


def identify_priority(row):
    category = str(row["category"] or "")
    reports = int(row["reports"] or 0)
    source_confidence = float(row["source_confidence"] or 0)
    score = int(row["score"] or 0)
    last_seen = str(row["last_seen"] or "")

    safe_reports = int(row["safe_reports"] or 0)
    fraud_reports = int(row["fraud_reports"] or 0)
    telemarketing_reports = int(row["telemarketing_reports"] or 0)

    fraud_like = 1 if category in {"fraud", "scam"} else 0

    return (
        fraud_reports,
        telemarketing_reports,
        -safe_reports,
        fraud_like,
        source_confidence,
        reports,
        score,
        last_seen,
    )


# ------------------------------------------------------------
# queries
# ------------------------------------------------------------


def fetch_block_rows(conn, limit: int):
    columns = raw_numbers_columns(conn)
    select_feedback_fields = feedback_select_fields("r", columns)

    query = f"""
        SELECT
            s.number,
            s.score,
            s.action,
            s.label,
            s.category,
            s.reports,
            {select_feedback_fields},
            s.source_confidence,
            s.last_seen,
            r.source,
            r.source_detail,
            r.prefix_official,
            r.scam_flag
        FROM scored_numbers s
        LEFT JOIN raw_numbers r ON r.number = s.number
        WHERE (
            s.action = 'block'
            OR (
                s.action = 'identify'
                AND s.category IN ('fraud', 'scam', 'spam', 'telemarketing', 'demarchage', 'démarchage')
            )
        )
        ORDER BY
            s.last_seen DESC,
            s.score DESC
        LIMIT ?
    """

    return conn.execute(query, (limit,))


def fetch_identify_rows(conn, limit: int):
    columns = raw_numbers_columns(conn)
    select_feedback_fields = feedback_select_fields("s", columns)

    query = f"""
        SELECT
            s.number,
            s.score,
            s.action,
            s.label,
            s.category,
            s.reports,
            {select_feedback_fields},
            s.source_confidence,
            s.last_seen
        FROM scored_numbers s
        WHERE s.action = 'identify'
        ORDER BY
            s.last_seen DESC,
            s.score DESC
        LIMIT ?
    """

    return conn.execute(query, (limit,))


# ------------------------------------------------------------
# export
# ------------------------------------------------------------


def build_device_dataset(conn):
    previous_state = {}
    if STATE_FILE.exists():
        try:
            with STATE_FILE.open("r", encoding="utf-8") as f:
                previous_state = json.load(f)
        except Exception:
            previous_state = {}

    previous_generated_at = parse_generated_at(previous_state.get("generated_at")) if previous_state else None

    # Force full rebuild when TEST_BLOCK_LIMIT is active (debug mode)
    if TEST_BLOCK_LIMIT is not None:
        recent_rows = []
    else:
        if previous_state and previous_generated_at is not None:
            recent_rows = fetch_recent_scored_rows(conn, previous_generated_at.isoformat())
            if not recent_rows:
                return build_unchanged_device_dataset(previous_state)
        else:
            recent_rows = []


    previous_blocked = {int(n) for n in previous_state.get("blocked_numbers", []) if str(n).isdigit()}
    previous_identified = {
        int(item["number"]): {
            "number": int(item["number"]),
            "label": item.get("label", "Spam suspect")
        }
        for item in previous_state.get("identified_numbers", [])
        if str(item.get("number", "")).isdigit()
    }

    block_rows = None
    identify_rows = None
    blocked_numbers = []
    seen_blocked = set()
    USE_INCREMENTAL = False
    identified_numbers = []

    # ------------------------------------------------------------
    # incremental diff and real incremental merge
    # ------------------------------------------------------------
    # (delta will be recomputed after dataset build)
    

    if previous_state and previous_generated_at is not None:
        # real incremental path only when the changed scored set stays small enough
        if recent_rows and len(recent_rows) < 5000:
            merged_blocked = set(previous_blocked)
            merged_identify = dict(previous_identified)

            for row in recent_rows:
                normalized = normalize_callkit_number(row["number"])
                if not normalized:
                    continue
                int_value = int(normalized)
                action = str(row["action"] or "").strip()
                category = str(row["category"] or "").strip().lower()

                # remove stale representation first
                merged_blocked.discard(int_value)
                merged_identify.pop(int_value, None)

                if action == "block":
                    merged_blocked.add(int_value)
                elif action == "identify":
                    if category == "safe":
                        continue
                    merged_identify[int_value] = {
                        "number": int_value,
                        "label": str(row["label"] or ("Fraud suspected" if category in {"fraud", "scam"} else "Spam suspect")),
                    }

            if len(merged_blocked) > MAX_CALLKIT_BLOCKS:
                merged_blocked = set(sorted(merged_blocked)[:MAX_CALLKIT_BLOCKS])
            blocked_numbers = sorted(merged_blocked)
            if TEST_BLOCK_LIMIT is not None:
                blocked_numbers = blocked_numbers[:TEST_BLOCK_LIMIT]

            identified_numbers = sorted(
                merged_identify.values(),
                key=lambda item: item["number"]
            )
            if len(identified_numbers) > MAX_IDENTIFIES:
                identified_numbers = identified_numbers[:MAX_IDENTIFIES]

            USE_INCREMENTAL = True
        elif False:
            # dead fallback intentionally disabled; final delta is recomputed from the built dataset
            pass

    # Full fetch path only when incremental mode is not active
    if not USE_INCREMENTAL:
        block_rows = sorted(fetch_block_rows(conn, BLOCK_FETCH_LIMIT), key=block_priority, reverse=True)
        identify_rows = sorted(fetch_identify_rows(conn, MAX_IDENTIFIES), key=identify_priority, reverse=True)

        limit = TEST_BLOCK_LIMIT if TEST_BLOCK_LIMIT is not None else MAX_CALLKIT_BLOCKS

        for row in block_rows or []:
            if len(blocked_numbers) >= limit:
                break
            normalized = normalize_callkit_number(row["number"])
            if not normalized:
                continue
            int_value = int(normalized)
            if int_value in seen_blocked:
                continue
            seen_blocked.add(int_value)
            blocked_numbers.append(int_value)

        identified_numbers = []
        seen_identify = set()

        for row in identify_rows or []:
            normalized = normalize_callkit_number(row["number"])
            if not normalized:
                continue
            int_value = int(normalized)
            if int_value in seen_blocked:
                continue
            if int_value in seen_identify:
                continue
            category = str(row["category"] or "").strip().lower()
            if category == "safe":
                continue
            seen_identify.add(int_value)
            identified_numbers.append(
                {
                    "number": int_value,
                    "label": str(row["label"] or ("Fraud suspected" if category in {"fraud", "scam"} or int(row["fraud_reports"] or 0) >= 2 else "Spam suspect")),
                }
            )
            if len(identified_numbers) >= MAX_IDENTIFIES:
                break

    # Enforce strict deduplication + ordering required by CallKit
    blocked_numbers = sorted({int(n) for n in blocked_numbers if str(n).isdigit()})
    if len(blocked_numbers) > MAX_CALLKIT_BLOCKS:
        blocked_numbers = blocked_numbers[:MAX_CALLKIT_BLOCKS]
    identified_numbers = sorted(
        identified_numbers,
        key=lambda item: item["number"]
    )
    # FINAL SAFETY: enforce strict int typing (no strings survive)
    blocked_numbers = [int(n) for n in blocked_numbers]
    identified_numbers = [
        {
            "number": int(item["number"]),
            "label": str(item.get("label", "Spam suspect"))
        }
        for item in identified_numbers
    ]
    # Final delta recomputation from the final exported dataset
    final_blocked = set(blocked_numbers)
    final_identified_map = {item["number"]: item for item in identified_numbers}
    added_blocks = final_blocked - previous_blocked
    removed_blocks = previous_blocked - final_blocked
    added_identify = set(final_identified_map) - set(previous_identified)
    removed_identify = set(previous_identified) - set(final_identified_map)

    total_scored = conn.execute("SELECT COUNT(*) FROM scored_numbers").fetchone()[0]

    return {
        "version": int(previous_state.get("version", 1)) + 1,
        "generated_at": now() + "_v" + str(int(previous_state.get("version", 1)) + 1),
        "total_scored": int(total_scored),
        "max_callkit_blocks": MAX_CALLKIT_BLOCKS,
        "blocked_numbers": blocked_numbers,
        "identified_numbers": identified_numbers,
        "blocked_numbers_count": len(blocked_numbers),
        "identified_numbers_count": len(identified_numbers),
        "incremental_mode": USE_INCREMENTAL,
        "incremental_reason": "recent_scored_rows" if USE_INCREMENTAL else "full_rebuild",
        "delta": {
            "added_blocks": len(added_blocks),
            "removed_blocks": len(removed_blocks),
            "added_identify": len(added_identify),
            "removed_identify": len(removed_identify),
        },
    }


def main():
    conn = get_connection()

    try:
        device = build_device_dataset(conn)

        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with OUTPUT_FILE.open("w", encoding="utf-8") as f:
            json.dump(device, f, ensure_ascii=False, separators=(",", ":"))
            f.write("\n")

        sms_filter_numbers = build_sms_filter_numbers(device)
        write_sms_filter_sqlite(
            SMS_FILTER_FILE,
            device.get("version", 1),
            device.get("generated_at", now()),
            sms_filter_numbers,
        )

        # Skip rebuild only when the exported dataset delta is strictly zero
        delta = device.get("delta", {}) or {}
        live_lookup_unchanged = (
            device.get("incremental_mode")
            and int(delta.get("added_blocks", 0)) == 0
            and int(delta.get("removed_blocks", 0)) == 0
            and int(delta.get("added_identify", 0)) == 0
            and int(delta.get("removed_identify", 0)) == 0
        )

        if live_lookup_unchanged:
            print("ℹ️ live lookup unchanged — skipping rebuild")
            live_lookup_export = []
        else:
            live_lookup_export = build_live_lookup_export(conn, limit=100_000)
            LIVE_LOOKUP_FILE.parent.mkdir(parents=True, exist_ok=True)
            with LIVE_LOOKUP_FILE.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "number_e164",
                        "label",
                        "category",
                        "confidence",
                        "risk_level",
                        "source",
                        "updated_at",
                    ],
                )
                writer.writeheader()
                writer.writerows(live_lookup_export)

        # Ensure consistency with push_updates (output dataset)
        output_dir_file = BASE_DIR / "output" / "spam-database.json"
        output_dir_file.parent.mkdir(parents=True, exist_ok=True)
        with output_dir_file.open("w", encoding="utf-8") as f:
            json.dump(device, f, ensure_ascii=False, separators=(",", ":"))
            f.write("\n")

        # persist state for incremental next runs
        with STATE_FILE.open("w", encoding="utf-8") as f:
            json.dump(device, f, ensure_ascii=False, separators=(",", ":"))
            f.write("\n")

        invalid_block_rows = 0
        invalid_identify_rows = 0

        print("SQLite device dataset exported")
        print("Output:", OUTPUT_FILE)
        print("Live lookup output:", LIVE_LOOKUP_FILE)
        print("SMS filter output:", SMS_FILTER_FILE)
        print("Blocked:", len(device["blocked_numbers"]))
        print("Identify:", len(device["identified_numbers"]))
        print("Live lookup items:", len(live_lookup_export))
        print("SMS filter numbers:", len(sms_filter_numbers))
        print("Invalid blocked numbers skipped:", invalid_block_rows)
        print("Invalid identify numbers skipped:", invalid_identify_rows)
        print("CallKit block cap:", MAX_CALLKIT_BLOCKS)

    finally:
        conn.close()


if __name__ == "__main__":
    main()
