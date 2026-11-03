"""The compose stack shares the CVE database cache (EB-047, EB-048)."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = yaml.safe_load(
    (ROOT / "cloudsneeker" / "deploy" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
)
CACHE = "/var/cache/cloudsneeker/vuln-db"


def _service(name: str) -> dict:
    return COMPOSE["services"][name]


def test_worker_writes_the_shared_vulnerability_database():
    worker = _service("cloudsneeker-worker")
    assert f"./_data/vuln-db:{CACHE}" in worker["volumes"]
    assert worker["environment"]["CLOUDSNEEKER_VULN_DB_CACHE_DIR"] == CACHE


def test_api_reads_the_vulnerability_database_read_only():
    api = _service("cloudsneeker-api")
    assert f"./_data/vuln-db:{CACHE}:ro" in api["volumes"]
    assert api["environment"]["CLOUDSNEEKER_VULN_DB_CACHE_DIR"] == CACHE
    assert "CLOUDSNEEKER_API_VERSION" in api["environment"][
        "CLOUDSNEEKER_RELEASE_VERSION"
    ]


def test_init_hands_the_cache_to_the_app_user():
    init = _service("api-init")
    assert "./_data/vuln-db:/vuln-db" in init["volumes"]
    assert "/vuln-db" in " ".join(init["command"])
