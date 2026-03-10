import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Optional

import requests
from bs4 import BeautifulSoup

ARCEP_URL = "https://www.arcep.fr/actualites/actualites-et-communiques/detail/n/plan-de-numerotation-050922.html"

DEFAULT_OUTPUT = "spam-database.json"
TIMEOUT = 20

PHONE_RE = re.compile(r"(?:\+33|0)\s*[1-9](?:[\s.-]*\d){8}")
SPAM_KEYWORDS = {
    "aggressive": [
        "arnaque", "fraude", "frauduleux", "usurpation", "escroquerie", "phishing",
        "spoof", "vishing", "sms frauduleux", "arnaque bancaire", "arnaque colis",
    ],
    "soft": [
        "démarchage", "telemarketing", "télémarketing", "energie", "énergie",
        "assurance", "mutuelle", "btp", "rénovation", "sondage", "centre d'appel",
    ],
}


def normalize_phone(raw: str) -> Optional[str]:
    digits = re.sub(r"\D", "", raw)
    if digits.startswith("33") and len(digits) == 11:
        digits = "0" + digits[2:]
    if len(digits) != 10:
        return None
    if not digits.startswith("0"):
        return None
    return digits


@dataclass
class IdentifiedEntry:
    number: str
    label: str


class SpamDatabaseBuilder:
    def __init__(self) -> None:
        self.blocked_numbers: set[str] = set()
        self.identified_numbers: dict[str, str] = {}
        self.prefixes: list[str] = []

    def add_blocked(self, numbers: Iterable[str]) -> None:
        for n in numbers:
            norm = normalize_phone(n)
            if norm:
                self.blocked_numbers.add(norm)

    def add_identified(self, entries: Iterable[IdentifiedEntry]) -> None:
        for entry in entries:
            norm = normalize_phone(entry.number)
            if norm and norm not in self.blocked_numbers:
                self.identified_numbers[norm] = entry.label

    def set_prefixes(self, prefixes: list[str]) -> None:
        self.prefixes = prefixes

    def export(self) -> dict:
        return {
            "version": 1,
            "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "blocked_numbers": sorted(self.blocked_numbers),
            "identified_numbers": [
                {"number": n, "label": self.identified_numbers[n]} for n in sorted(self.identified_numbers)
            ],
            "telemarketing_prefixes": self.prefixes,
        }


def fetch_html(url: str) -> str:
    r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "CallShieldBot/1.0"})
    r.raise_for_status()
    return r.text


def scrape_arcep_prefixes() -> list[str]:
    html = fetch_html(ARCEP_URL)
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)
    # Official metropolitan prefixes from ARCEP
    matches = re.findall(r"\b(0162|0163|0270|0271|0377|0378|0424|0425|0568|0569|0948|0949)\b", text)
    return sorted(set(matches))


def classify_text_blob(url: str, label_hint: str) -> tuple[list[str], list[IdentifiedEntry]]:
    html = fetch_html(url)
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True).lower()
    found = set()
    for m in PHONE_RE.findall(text):
        norm = normalize_phone(m)
        if norm:
            found.add(norm)

    aggressive = any(k in text for k in SPAM_KEYWORDS["aggressive"])
    soft = any(k in text for k in SPAM_KEYWORDS["soft"])

    blocked: list[str] = []
    identified: list[IdentifiedEntry] = []
    if aggressive:
        blocked = sorted(found)
    elif soft:
        identified = [IdentifiedEntry(number=n, label=label_hint) for n in sorted(found)]
    return blocked, identified


def load_source_manifest(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("sources manifest must be a JSON list")
    return data


def build_database(sources_manifest: Optional[str]) -> dict:
    builder = SpamDatabaseBuilder()
    prefixes = scrape_arcep_prefixes()
    builder.set_prefixes(prefixes)

    if sources_manifest:
        sources = load_source_manifest(sources_manifest)
        for src in sources:
            url = src["url"]
            kind = src.get("kind", "identified")
            label = src.get("label", "Spam probable")
            try:
                blocked, identified = classify_text_blob(url, label)
                if kind == "blocked":
                    builder.add_blocked(blocked)
                elif kind == "identified":
                    builder.add_identified(identified)
                else:
                    # auto mode: aggressive -> blocked, soft -> identified
                    builder.add_blocked(blocked)
                    builder.add_identified(identified)
                print(f"OK: {url} -> blocked={len(blocked)} identified={len(identified)}")
            except Exception as e:
                print(f"SKIP: {url} -> {e}", file=sys.stderr)

    return builder.export()


def push_to_github(repo: str, token: str, path_in_repo: str, content: str, message: str) -> None:
    api = f"https://api.github.com/repos/{repo}/contents/{path_in_repo}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    current = requests.get(api, headers=headers, timeout=TIMEOUT)
    sha = None
    if current.status_code == 200:
        sha = current.json().get("sha")
    import base64
    payload = {
        "message": message,
        "content": base64.b64encode(content.encode("utf-8")).decode("utf-8"),
        "branch": "main",
    }
    if sha:
        payload["sha"] = sha
    r = requests.put(api, headers=headers, json=payload, timeout=TIMEOUT)
    r.raise_for_status()


def main() -> int:
    parser = argparse.ArgumentParser(description="Build CallShield spam-database.json from safe/allowed sources.")
    parser.add_argument("--sources", help="Path to JSON manifest of approved sources", default=None)
    parser.add_argument("--output", help="Output JSON path", default=DEFAULT_OUTPUT)
    parser.add_argument("--push-github", action="store_true", help="Push output to GitHub repo via API")
    parser.add_argument("--github-repo", help="owner/repo, e.g. Almorantino/callshield-spam-database")
    parser.add_argument("--github-path", default="spam-database.json")
    args = parser.parse_args()

    db = build_database(args.sources)
    content = json.dumps(db, ensure_ascii=False, indent=2)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Wrote {args.output} with {len(db['blocked_numbers'])} blocked and {len(db['identified_numbers'])} identified entries")

    if args.push_github:
        token = os.environ.get("GITHUB_TOKEN")
        if not token or not args.github_repo:
            raise SystemExit("--push-github requires GITHUB_TOKEN and --github-repo")
        push_to_github(
            repo=args.github_repo,
            token=token,
            path_in_repo=args.github_path,
            content=content,
            message="Update spam database",
        )
        print("Pushed to GitHub")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
