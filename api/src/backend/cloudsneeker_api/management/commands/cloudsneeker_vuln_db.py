"""Show or refresh the shared vulnerability database cache (EB-047).

    python manage.py cloudsneeker_vuln_db             # show the current snapshot
    python manage.py cloudsneeker_vuln_db --refresh   # download a new snapshot

Exits non-zero when the cache is not configured, has no snapshot, or the
snapshot is too old for scans to use.
"""

from __future__ import annotations

from cloudsneeker_api.services import vuln_db
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Show or refresh the shared vulnerability database cache."

    def add_arguments(self, parser):
        parser.add_argument(
            "--refresh",
            action="store_true",
            help="Download a new snapshot and make it current.",
        )

    def handle(self, *args, **options):
        root = vuln_db.cache_root()
        if root is None:
            raise CommandError(f"{vuln_db.CACHE_DIR_ENV} is not set.")
        if options["refresh"]:
            try:
                vuln_db.refresh(root)
            except vuln_db.VulnDbError as error:
                raise CommandError(str(error)) from None
        snapshot = vuln_db.current_snapshot(root)
        if snapshot is None:
            raise CommandError(f"No usable snapshot in {root}.")
        age_hours = snapshot.age().total_seconds() / 3600
        self.stdout.write(
            f"snapshot={snapshot.path.name} refreshed_at="
            f"{snapshot.refreshed_at.isoformat()} age_hours={age_hours:.1f} "
            f"java_db={snapshot.java_db}"
        )
        if not snapshot.is_fresh():
            raise CommandError("The snapshot is too old; scans download their own.")
        self.stdout.write(self.style.SUCCESS("Scans use the shared snapshot."))
