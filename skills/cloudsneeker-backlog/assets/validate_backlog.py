"""Validate the enterprise backlog table and the launch plan that refers to it.

Checks ``knowledge-base/enterprise-backlog.md``: every row has ten cells, IDs
are unique and well-formed, and Priority, Effort, Status and Owner hold an
allowed value. Then checks that every ``EB-###`` named in
``knowledge-base/saas-launch-plan.md`` exists in the backlog.

Usage:
    python skills/cloudsneeker-backlog/assets/validate_backlog.py [--summary]

Exit code is 1 when a rule is broken.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
BACKLOG = REPO_ROOT / "knowledge-base" / "enterprise-backlog.md"
LAUNCH_PLAN = REPO_ROOT / "knowledge-base" / "saas-launch-plan.md"

COLUMNS = 10
ID_PATTERN = re.compile(r"^EB-\d{3}$")
ROW_START = re.compile(r"^\s*\|\s*EB-")
ID_REFERENCE = re.compile(r"\bEB-\d{3}\b")
PRIORITIES = {"P0", "P1", "P2"}
EFFORTS = {"S", "M", "L"}
STATUSES = {"Todo", "In progress", "Done (pending deploy)", "Done"}
OWNERS = {"Buildable", "Blocked: needs owner"}


def parse_rows(text: str) -> list[tuple[int, list[str]]]:
    """Return (line number, cells) for every backlog row."""
    rows = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not ROW_START.match(line):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split(" | ")]
        rows.append((number, cells))
    return rows


def validate(rows: list[tuple[int, list[str]]]) -> list[str]:
    """Return one message per broken rule."""
    errors = []
    seen: dict[str, int] = {}
    for number, cells in rows:
        where = f"{BACKLOG.name}:{number}"
        if len(cells) != COLUMNS:
            errors.append(f"{where}: expected {COLUMNS} cells, found {len(cells)}")
            continue
        item_id, _, _, priority, effort, _, _, status, owner, criteria = cells
        if not ID_PATTERN.match(item_id):
            errors.append(f"{where}: malformed ID {item_id!r}")
        if item_id in seen:
            errors.append(f"{where}: {item_id} already used on line {seen[item_id]}")
        seen[item_id] = number
        if priority not in PRIORITIES:
            errors.append(f"{where}: {item_id} priority {priority!r} is not allowed")
        if effort not in EFFORTS:
            errors.append(f"{where}: {item_id} effort {effort!r} is not allowed")
        if status not in STATUSES:
            errors.append(f"{where}: {item_id} status {status!r} is not allowed")
        if owner not in OWNERS:
            errors.append(f"{where}: {item_id} owner {owner!r} is not allowed")
        if not criteria:
            errors.append(f"{where}: {item_id} has no acceptance criteria")
    return errors


def validate_launch_plan(known_ids: set[str]) -> list[str]:
    """Return one message per launch-plan reference to an unknown item."""
    if not LAUNCH_PLAN.exists():
        return []
    errors = []
    for number, line in enumerate(
        LAUNCH_PLAN.read_text(encoding="utf-8").splitlines(), start=1
    ):
        for item_id in ID_REFERENCE.findall(line):
            if item_id not in known_ids:
                errors.append(
                    f"{LAUNCH_PLAN.name}:{number}: {item_id} is not in the backlog"
                )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--summary", action="store_true", help="print counts by status and owner"
    )
    args = parser.parse_args()

    rows = parse_rows(BACKLOG.read_text(encoding="utf-8"))
    if not rows:
        print(f"error: no backlog rows found in {BACKLOG}", file=sys.stderr)
        return 1

    errors = validate(rows)
    known_ids = {cells[0] for _, cells in rows}
    errors += validate_launch_plan(known_ids)

    if args.summary:
        complete = [cells for _, cells in rows if len(cells) == COLUMNS]
        by_status = Counter(cells[7] for cells in complete)
        open_by_owner = Counter(
            cells[8] for cells in complete if not cells[7].startswith("Done")
        )
        print(f"{len(rows)} items")
        for status, count in sorted(by_status.items()):
            print(f"  {status}: {count}")
        for owner, count in sorted(open_by_owner.items()):
            print(f"  open, {owner}: {count}")

    if errors:
        print("\n".join(errors))
        return 1
    print(f"OK: {len(rows)} backlog items are valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
