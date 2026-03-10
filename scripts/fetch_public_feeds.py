import json
import urllib.request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
FEEDS_FILE = BASE_DIR / "sources" / "feeds.json"
SOURCES_DIR = BASE_DIR / "sources"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, payload):
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def fetch_url(url: str):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CallShieldBot/1.0"
        }
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = resp.read()
    return json.loads(data.decode("utf-8"))


def normalize_payload(payload):
    if isinstance(payload, dict) and "numbers" in payload:
        return payload

    if isinstance(payload, list):
        return {"numbers": payload}

    return {"numbers": []}


def main():
    SOURCES_DIR.mkdir(parents=True, exist_ok=True)

    if not FEEDS_FILE.exists():
        print("No feeds.json found")
        return

    feeds = load_json(FEEDS_FILE).get("feeds", [])
    fetched = 0

    for feed in feeds:
        name = str(feed.get("name", "")).strip()
        url = str(feed.get("url", "")).strip()

        if not name or not url:
            continue

        try:
            payload = fetch_url(url)
            normalized = normalize_payload(payload)

            output_file = SOURCES_DIR / f"{name}.json"
            save_json(output_file, normalized)

            count = len(normalized.get("numbers", []))
            print(f"Fetched {name}: {count} numbers")
            fetched += 1

        except Exception as e:
            print(f"Failed {name}: {e}")

    print(f"Feed files fetched: {fetched}")


if __name__ == "__main__":
    main()
