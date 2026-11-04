"""Detection content release notes endpoint (EB-049)."""

from __future__ import annotations

import pytest
from cloudsneeker import content_releases
from django.urls import reverse

RELEASES = (
    {
        "version": "5.45.0",
        "current": True,
        "previous_version": "5.44.0",
        "released_at": None,
        "summary": {"checks_added": 1},
        "checks": {
            "added": [{"id": "s3_bucket_example", "title": "Example"}],
            "changed": [],
            "removed": [],
        },
        "frameworks": {"added": [], "changed": [], "removed": []},
    },
)


def test_packaged_notes_are_newest_first():
    releases = content_releases.load_releases()
    assert releases, "cloudsneeker/content/releases.json is not packaged"
    assert releases[0]["current"] is True
    assert all(not release["current"] for release in releases[1:])


def test_missing_notes_file_returns_no_releases(tmp_path, monkeypatch):
    monkeypatch.setattr(content_releases, "RELEASES_PATH", tmp_path / "missing.json")
    content_releases.load_releases.cache_clear()
    try:
        assert content_releases.load_releases() == ()
    finally:
        content_releases.load_releases.cache_clear()


@pytest.mark.django_db
class TestContentReleasesEndpoint:
    def test_returns_releases_newest_first(self, authenticated_client, monkeypatch):
        monkeypatch.setattr(
            "cloudsneeker_api.views_content_releases.load_releases", lambda: RELEASES
        )
        response = authenticated_client.get(reverse("content-releases"))
        assert response.status_code == 200, response.content
        data = response.json()["data"]
        assert [item["id"] for item in data] == ["5.45.0"]
        assert data[0]["type"] == "cloudsneeker-content-releases"
        assert data[0]["attributes"]["checks"]["added"][0]["id"] == "s3_bucket_example"

    def test_requires_authentication(self, client):
        assert client.get(reverse("content-releases")).status_code == 401
