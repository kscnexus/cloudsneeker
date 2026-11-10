"""Exploit intelligence for CVE findings (EB-022).

Two public feeds rank CVEs by how likely they are to be exploited:

* EPSS (Exploit Prediction Scoring System): a daily probability (0 to 1)
  that a CVE is exploited in the next 30 days, plus its percentile.
* CISA KEV (Known Exploited Vulnerabilities): CVEs with confirmed
  exploitation in the wild, the date added, the federal due date and whether
  ransomware campaigns use them.

A daily Celery Beat task (``cloudsneeker-refresh-vuln-intel``) downloads
both feeds into ``VulnerabilityIntel``, one row per CVE, shared by every
tenant (the data is public). Each feed refreshes on its own: if one download
fails, the other still updates and the failed one keeps its last good data.

Findings are not changed. The area findings list joins on ``check_id`` (the
CVE id of an imported vulnerability) when it reads, so findings stored
before this existed get scores too.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

import requests
from api.db_router import MainRouter
from cloudsneeker_api.models import VulnerabilityIntel, VulnerabilityIntelFeed
from django.db import transaction
from django.db.models import OuterRef, QuerySet, Subquery

logger = logging.getLogger(__name__)

EPSS_URL_ENV = "CLOUDSNEEKER_EPSS_URL"
KEV_URL_ENV = "CLOUDSNEEKER_KEV_URL"
DEFAULT_EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
FEED_EPSS = VulnerabilityIntelFeed.Name.EPSS
FEED_KEV = VulnerabilityIntelFeed.Name.KEV

DOWNLOAD_TIMEOUT_SECONDS = 120
# The EPSS file is about 2 MB compressed; anything far larger is not the feed.
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
BATCH_SIZE = 5000
MAX_ERROR_LENGTH = 500
USER_AGENT = "cloudsneeker-vuln-intel/1"

EPSS_FIELDS = ("epss_score", "epss_percentile")
KEV_FIELDS = (
    "kev",
    "kev_date_added",
    "kev_due_date",
    "kev_ransomware",
    "kev_name",
    "kev_required_action",
)


class FeedError(RuntimeError):
    """A feed could not be downloaded or parsed."""


@dataclass(frozen=True)
class EpssScore:
    cve_id: str
    score: float
    percentile: float


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    date_added: date | None
    due_date: date | None
    ransomware: bool
    name: str
    required_action: str


# --- Parsing ------------------------------------------------------------------


def _is_cve(value: str) -> bool:
    return value.startswith("CVE-") and len(value) <= 32


def parse_epss(payload: bytes) -> tuple[str, list[EpssScore]]:
    """Version label and scores from the EPSS CSV (gzip or plain).

    The file starts with a ``#model_version:...,score_date:...`` comment line,
    then a ``cve,epss,percentile`` header.

    Raises:
        FeedError: The payload is not an EPSS file.
    """
    if payload[:2] == b"\x1f\x8b":
        try:
            payload = gzip.decompress(payload)
        except (OSError, EOFError) as error:
            raise FeedError(f"EPSS file is not valid gzip: {error}") from error
    text = payload.decode("utf-8", errors="replace")
    lines = text.splitlines()
    version = ""
    if lines and lines[0].startswith("#"):
        version = _epss_version(lines[0])
        lines = lines[1:]
    reader = csv.DictReader(lines)
    if not reader.fieldnames or not {"cve", "epss", "percentile"} <= set(
        reader.fieldnames
    ):
        raise FeedError("EPSS file has no cve,epss,percentile header.")
    scores: list[EpssScore] = []
    for row in reader:
        cve = (row.get("cve") or "").strip().upper()
        if not _is_cve(cve):
            continue
        try:
            score = float(row["epss"])
            percentile = float(row["percentile"])
        except (TypeError, ValueError):
            continue
        if 0.0 <= score <= 1.0 and 0.0 <= percentile <= 1.0:
            scores.append(EpssScore(cve, score, percentile))
    if not scores:
        raise FeedError("EPSS file has no scores.")
    return version, scores


def _epss_version(comment: str) -> str:
    """``score_date`` (the day scored) from the comment line, else the model."""
    parts = dict(
        part.split(":", 1) for part in comment.lstrip("#").split(",") if ":" in part
    )
    score_date = parts.get("score_date", "").strip()
    return (score_date[:10] if score_date else parts.get("model_version", ""))[:64]


def _date(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None


def parse_kev(payload: bytes) -> tuple[str, list[KevEntry]]:
    """Catalog version and entries from the CISA KEV JSON feed.

    Raises:
        FeedError: The payload is not the KEV catalog.
    """
    try:
        data = json.loads(payload)
    except ValueError as error:
        raise FeedError(f"KEV feed is not JSON: {error}") from error
    items = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise FeedError("KEV feed has no vulnerabilities list.")
    entries: dict[str, KevEntry] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").strip().upper()
        if not _is_cve(cve):
            continue
        entries[cve] = KevEntry(
            cve_id=cve,
            date_added=_date(item.get("dateAdded")),
            due_date=_date(item.get("dueDate")),
            ransomware=str(item.get("knownRansomwareCampaignUse") or "").lower()
            == "known",
            name=str(item.get("vulnerabilityName") or "")[:300],
            required_action=str(item.get("requiredAction") or "")[:1000],
        )
    if not entries:
        raise FeedError("KEV feed has no CVE entries.")
    return str(data.get("catalogVersion") or "")[:64], list(entries.values())


# --- Download and store ---------------------------------------------------------


def _url(env: str, default: str) -> str:
    return os.environ.get(env, "").strip() or default


def download(url: str) -> bytes:
    """GET ``url`` with a timeout and a size cap.

    Raises:
        FeedError: Network error, HTTP error or an oversized response.
    """
    try:
        with requests.get(
            url,
            timeout=DOWNLOAD_TIMEOUT_SECONDS,
            stream=True,
            headers={"User-Agent": USER_AGENT},
        ) as response:
            response.raise_for_status()
            buffer = io.BytesIO()
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                buffer.write(chunk)
                if buffer.tell() > MAX_DOWNLOAD_BYTES:
                    raise FeedError("Feed is larger than the download limit.")
            return buffer.getvalue()
    except requests.RequestException as error:
        raise FeedError(f"Download failed: {error}") from error


def _batches(items: Iterable[Any], size: int = BATCH_SIZE) -> Iterator[list[Any]]:
    batch: list[Any] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def _manager():
    return VulnerabilityIntel.objects.using(MainRouter.admin_db)


def store_epss(scores: list[EpssScore]) -> int:
    """Upsert EPSS columns; KEV columns of existing rows are left alone."""
    with transaction.atomic(using=MainRouter.admin_db):
        for batch in _batches(scores):
            _manager().bulk_create(
                [
                    VulnerabilityIntel(
                        cve_id=score.cve_id,
                        epss_score=score.score,
                        epss_percentile=score.percentile,
                    )
                    for score in batch
                ],
                update_conflicts=True,
                unique_fields=["cve_id"],
                update_fields=[*EPSS_FIELDS, "updated_at"],
            )
    return len(scores)


def store_kev(entries: list[KevEntry]) -> int:
    """Upsert KEV columns and clear the flag on CVEs no longer listed."""
    listed = [entry.cve_id for entry in entries]
    with transaction.atomic(using=MainRouter.admin_db):
        for batch in _batches(entries):
            _manager().bulk_create(
                [
                    VulnerabilityIntel(
                        cve_id=entry.cve_id,
                        kev=True,
                        kev_date_added=entry.date_added,
                        kev_due_date=entry.due_date,
                        kev_ransomware=entry.ransomware,
                        kev_name=entry.name,
                        kev_required_action=entry.required_action,
                    )
                    for entry in batch
                ],
                update_conflicts=True,
                unique_fields=["cve_id"],
                update_fields=[*KEV_FIELDS, "updated_at"],
            )
        _manager().filter(kev=True).exclude(cve_id__in=listed).update(
            kev=False,
            kev_date_added=None,
            kev_due_date=None,
            kev_ransomware=False,
            kev_name="",
            kev_required_action="",
        )
    return len(entries)


def _record(name: str, *, version: str = "", count: int = 0, error: str = "") -> None:
    now = datetime.now(UTC)
    feeds = VulnerabilityIntelFeed.objects.using(MainRouter.admin_db)
    feed, _ = feeds.get_or_create(name=name)
    feed.last_attempt_at = now
    feed.last_error = error[:MAX_ERROR_LENGTH]
    if not error:
        feed.refreshed_at = now
        feed.version = version
        feed.record_count = count
    feed.save(using=MainRouter.admin_db)


def refresh_feed(name: str) -> dict[str, Any]:
    """Download, parse and store one feed; record the outcome on its row."""
    if name == FEED_EPSS:
        url, parse, store = _url(EPSS_URL_ENV, DEFAULT_EPSS_URL), parse_epss, store_epss
    elif name == FEED_KEV:
        url, parse, store = _url(KEV_URL_ENV, DEFAULT_KEV_URL), parse_kev, store_kev
    else:
        raise ValueError(f"Unknown feed: {name}")
    try:
        version, records = parse(download(url))
        count = store(records)
    except FeedError as error:
        logger.warning("Exploit intelligence feed %s not refreshed: %s", name, error)
        _record(name, error=str(error))
        return {"feed": name, "refreshed": False, "error": str(error)}
    _record(name, version=version, count=count)
    return {"feed": name, "refreshed": True, "version": version, "count": count}


def refresh() -> list[dict[str, Any]]:
    """Refresh both feeds; one failing does not stop the other."""
    return [refresh_feed(FEED_EPSS), refresh_feed(FEED_KEV)]


# --- Read side --------------------------------------------------------------------


def empty_exploit() -> dict[str, Any]:
    return {
        "epss_score": None,
        "epss_percentile": None,
        "known_exploited": False,
        "kev_date_added": None,
        "kev_due_date": None,
        "kev_ransomware": False,
        "kev_required_action": "",
    }


def _exploit(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "epss_score": row["epss_score"],
        "epss_percentile": row["epss_percentile"],
        "known_exploited": bool(row["kev"]),
        "kev_date_added": row["kev_date_added"],
        "kev_due_date": row["kev_due_date"],
        "kev_ransomware": bool(row["kev_ransomware"]),
        "kev_required_action": row["kev_required_action"] or "",
    }


def exploit_by_cve(cve_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Exploit fields per CVE id, for the CVEs that have any intelligence."""
    wanted = sorted({cve for cve in cve_ids if cve and _is_cve(cve)})
    if not wanted:
        return {}
    return {
        row["cve_id"]: _exploit(row)
        for row in VulnerabilityIntel.objects.filter(cve_id__in=wanted).values(
            "cve_id", *EPSS_FIELDS, *KEV_FIELDS
        )
    }


def known_exploited_ids() -> QuerySet:
    """Subquery of every CVE id in the KEV catalog."""
    return VulnerabilityIntel.objects.filter(kev=True).values("cve_id")


def epss_subquery(cve_field: str = "check_id") -> Subquery:
    """EPSS score of the CVE in ``cve_field`` of the outer query (or NULL)."""
    return Subquery(
        VulnerabilityIntel.objects.filter(cve_id=OuterRef(cve_field)).values(
            "epss_score"
        )[:1]
    )


def feed_status() -> list[dict[str, Any]]:
    """State of each feed for the content versions page."""
    rows = {
        feed.name: feed
        for feed in VulnerabilityIntelFeed.objects.using(MainRouter.admin_db).all()
    }
    status = []
    for name, label in VulnerabilityIntelFeed.Name.choices:
        feed = rows.get(name)
        status.append(
            {
                "id": name,
                "label": label,
                "version": (feed.version or None) if feed else None,
                "records": feed.record_count if feed and feed.refreshed_at else None,
                "refreshed_at": feed.refreshed_at if feed else None,
                "last_error": (feed.last_error or None) if feed else None,
            }
        )
    return status
