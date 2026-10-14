"""Service images keep their shell entrypoints executable."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_service_dockerfiles_mark_entrypoints_executable():
    api = (ROOT / "api" / "Dockerfile").read_text(encoding="utf-8")
    mcp = (ROOT / "mcp_server" / "Dockerfile").read_text(encoding="utf-8")
    assert "RUN chmod +x ./docker-entrypoint.sh # cloudsneeker-hook" in api
    assert "RUN chmod +x /app/entrypoint.sh # cloudsneeker-hook" in mcp
