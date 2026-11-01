"""Re-encrypt stored secrets with the current encryption key (EB-016).

    python manage.py cloudsneeker_rotate_secrets --check   # report only
    python manage.py cloudsneeker_rotate_secrets           # rewrite stale values

Run it after setting the new ``DJANGO_SECRETS_ENCRYPTION_KEY`` with the old
key in ``DJANGO_SECRETS_ENCRYPTION_KEY_PREVIOUS``. ``--check`` exits non-zero
while any value still needs a previous key, so it can gate removing the old
key. See ``knowledge-base/encryption-key-rotation.md``.
"""

from __future__ import annotations

from cloudsneeker_api.services import secret_rotation
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Re-encrypt stored secrets with the current encryption key."

    def add_arguments(self, parser):
        parser.add_argument(
            "--check",
            action="store_true",
            help="Only report; fail while values still need a previous key.",
        )

    def handle(self, *args, **options):
        check = options["check"]
        reports = secret_rotation.scan() if check else secret_rotation.rotate()
        stale = unreadable = 0
        for report in reports:
            stale += report.stale - report.rotated
            unreadable += report.unreadable
            self.stdout.write(
                f"{report.label}: current={report.current} stale={report.stale} "
                f"rotated={report.rotated} unreadable={report.unreadable}"
            )
            if report.unreadable_ids:
                self.stdout.write(
                    f"  unreadable ids: {', '.join(report.unreadable_ids[:20])}"
                )
        if unreadable:
            raise CommandError(
                f"{unreadable} value(s) cannot be read with any configured key. "
                "Add the key they were written with to "
                "DJANGO_SECRETS_ENCRYPTION_KEY_PREVIOUS and run again."
            )
        if check and stale:
            raise CommandError(
                f"{stale} value(s) still need a previous key. Run without --check."
            )
        self.stdout.write(self.style.SUCCESS("All stored secrets use the current key."))
