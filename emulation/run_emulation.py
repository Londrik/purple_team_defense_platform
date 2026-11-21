"""Controlled attack emulation script against OWASP Juice Shop."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import httpx


def load_vectors(payload_path: Path) -> dict[str, Any]:
    """Load attack vector definitions from a JSON file.

    Args:
        payload_path: Path to the JSON payload manifest.

    Returns:
        Parsed manifest dictionary containing base URL and vectors.
    """
    data = json.loads(payload_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("vectors"), list):
        raise ValueError("Invalid payload manifest format.")
    return data


def run_emulation(payload_path: Path, timeout: float = 5.0) -> list[dict[str, Any]]:
    """Execute HTTP requests for each configured attack vector.

    Args:
        payload_path: Path to the JSON payload manifest.
        timeout: Per-request HTTP timeout in seconds.

    Returns:
        List of execution result records for inspection.
    """
    manifest = load_vectors(payload_path)
    base_url = str(manifest.get("target_base_url", "http://localhost:3000")).rstrip("/")
    results: list[dict[str, Any]] = []

    with httpx.Client(timeout=timeout) as client:
        for item in manifest["vectors"]:
            vector_id = str(item["id"])
            technique = str(item["mitre_technique"])
            method = str(item.get("method", "GET")).upper()
            path = str(item["path"])
            url = f"{base_url}{path}"
            try:
                response = client.request(method, url)
                results.append(
                    {
                        "id": vector_id,
                        "mitre_technique": technique,
                        "url": url,
                        "status_code": response.status_code,
                        "reachable": True,
                    }
                )
            except httpx.HTTPError as exc:
                results.append(
                    {
                        "id": vector_id,
                        "mitre_technique": technique,
                        "url": url,
                        "status_code": None,
                        "reachable": False,
                        "error": str(exc),
                    }
                )
    return results


def main() -> int:
    """CLI entrypoint for running controlled emulation vectors."""
    parser = argparse.ArgumentParser(
        description="Run Juice Shop attack emulation vectors."
    )
    parser.add_argument(
        "--payloads",
        type=Path,
        default=Path("emulation/payloads/juice_shop_vectors.json"),
        help="Path to attack vectors JSON file.",
    )
    args = parser.parse_args()
    output = run_emulation(args.payloads)
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
