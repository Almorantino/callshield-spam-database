#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = BASE_DIR / "data" / "live-caller-id-pir"
LIVE_CALLER_ID_EXTENSION_BUNDLE_ID = "com.almorantino.callshield.CallShieldLiveCallerID"

# Base64 for CALLSHIELD_DEV_TOKEN. The iOS extension must use the same value as userTierToken.
DEFAULT_DEV_USER_TOKEN = "Q0FMTFNISUVMRF9ERVZfVE9LRU4="
DEFAULT_LOCAL_BASE_URL = "http://127.0.0.1:8080"
DEFAULT_ISSUER_REQUEST_URI = "http://127.0.0.1:8080/issue"
RLWE_PARAMETERS = "n_4096_logq_27_28_28_logt_5"


def write_json(path: Path, payload: dict):
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_process_config(data_dir: Path, name: str, entry_count_per_shard: int) -> dict:
    return {
        "databaseType": "keyword",
        "inputDatabase": str(data_dir / f"{name}.binpb"),
        "outputDatabase": str(data_dir / f"{name}-SHARD_ID.bin"),
        "outputPirParameters": str(data_dir / f"{name}-SHARD_ID.params.txtpb"),
        "rlweParameters": RLWE_PARAMETERS,
        "sharding": {
            "entryCountPerShard": entry_count_per_shard,
        },
        "trialsPerShard": 5,
    }


def build_service_config(
    data_dir: Path,
    dev_user_token: str,
    issuer_request_uri: str,
    block_shard_count: int,
    identity_shard_count: int,
) -> dict:
    return {
        "issuerRequestUri": issuer_request_uri,
        "users": [
            {
                "tier": "tier1",
                "tokens": [dev_user_token],
            },
        ],
        "usecases": [
            {
                "fileStem": str(data_dir / "block"),
                "name": f"{LIVE_CALLER_ID_EXTENSION_BUNDLE_ID}.block",
                "shardCount": block_shard_count,
            },
            {
                "fileStem": str(data_dir / "identity"),
                "name": f"{LIVE_CALLER_ID_EXTENSION_BUNDLE_ID}.identity",
                "shardCount": identity_shard_count,
            },
        ],
    }


def build_dev_client_config(base_url: str, dev_user_token: str) -> dict:
    return {
        "authorizationHeader": f"Bearer {dev_user_token}",
        "serviceURL": base_url,
        "swiftSnippet": (
            f'serviceURL: URL(string: "{base_url}")!,\n'
            f'tokenIssuerURL: URL(string: "{base_url}")!,\n'
            f'userTierToken: Data(base64Encoded: "{dev_user_token}")!'
        ),
        "tokenIssuerURL": base_url,
        "userTierTokenBase64": dev_user_token,
    }


def existing_shard_count(data_dir: Path, name: str) -> int:
    return len(sorted(data_dir.glob(f"{name}-*.params.txtpb")))


def resolve_pir_process_database(explicit_path: Optional[Path]) -> Optional[str]:
    if explicit_path:
        return str(explicit_path)

    env_path = os.environ.get("PIR_PROCESS_DATABASE")
    if env_path:
        return env_path

    return shutil.which("PIRProcessDatabase")


def require_inputs(data_dir: Path):
    missing = [name for name in ("block.binpb", "identity.binpb") if not (data_dir / name).exists()]
    if missing:
        raise FileNotFoundError(
            f"Missing {', '.join(missing)} in {data_dir}. "
            "Run scripts/export_live_caller_id_pir_dataset.py first."
        )


def run_pir_process_database(binary: str, config_file: Path):
    subprocess.run([binary, str(config_file)], check=True)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Process CallShield Live Caller ID datasets for Apple PIRService."
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--pir-process-database", type=Path, default=None)
    parser.add_argument("--dev-user-token", default=DEFAULT_DEV_USER_TOKEN)
    parser.add_argument("--local-base-url", default=DEFAULT_LOCAL_BASE_URL)
    parser.add_argument("--issuer-request-uri", default=DEFAULT_ISSUER_REQUEST_URI)
    parser.add_argument("--write-config-only", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    data_dir = args.data_dir
    require_inputs(data_dir)

    block_config = data_dir / "block-config.json"
    identity_config = data_dir / "identity-config.json"
    service_config = data_dir / "service-config.json"
    dev_client_config = data_dir / "dev-client-config.json"

    write_json(block_config, build_process_config(data_dir, "block", 50_000))
    write_json(identity_config, build_process_config(data_dir, "identity", 5_000))

    if not args.write_config_only:
        binary = resolve_pir_process_database(args.pir_process_database)
        if not binary:
            raise FileNotFoundError(
                "PIRProcessDatabase not found. Install/build Apple's swift-homomorphic-encryption "
                "PIRProcessDatabase and pass --pir-process-database or set PIR_PROCESS_DATABASE."
            )
        run_pir_process_database(binary, block_config)
        run_pir_process_database(binary, identity_config)

    block_shards = existing_shard_count(data_dir, "block")
    identity_shards = existing_shard_count(data_dir, "identity")
    if block_shards == 0:
        block_shards = 2
    if identity_shards == 0:
        identity_shards = 20

    write_json(
        service_config,
        build_service_config(
            data_dir,
            args.dev_user_token,
            args.issuer_request_uri,
            block_shards,
            identity_shards,
        ),
    )
    write_json(dev_client_config, build_dev_client_config(args.local_base_url, args.dev_user_token))

    print(f"Processed config files in {data_dir}")
    print(f"block shards: {block_shards}")
    print(f"identity shards: {identity_shards}")
    print(f"service config: {service_config}")
    print(f"dev client config: {dev_client_config}")


if __name__ == "__main__":
    main()
