"""Rewrite upstream display copy in a build tree.

Usage::

    python cloudsneeker/tools/rebrand.py --check [--root DIR]
    python cloudsneeker/tools/rebrand.py --report [--root DIR]
    python cloudsneeker/tools/rebrand.py --apply --root DIR

``--check`` is a dry run that lists how many files each rule would change and
fails when a required rule no longer matches anything, which signals that an
upstream merge moved the text the rule was written for. ``--apply`` rewrites
files in place and refuses to touch a git work tree unless ``--allow-git-tree``
is passed, so the source checkout stays byte-identical to upstream.
"""

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore[no-redef]

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent.parent
DEFAULT_RULES = TOOLS_DIR / "rebrand.rules.toml"

sys.path.insert(0, str(REPO_ROOT))

from cloudsneeker.brand import Brand, load_brand  # noqa: E402
from cloudsneeker.tools.pathmatch import matches_any, read_text, to_posix  # noqa: E402

SKIP_DIRS = {".git", "node_modules", ".venv", ".next", "__pycache__", "_data"}


@dataclass(frozen=True)
class Rule:
    """One ordered regex replacement."""

    id: str
    pattern: re.Pattern[str]
    replacement: str
    include: tuple[str, ...]
    optional: bool = False


@dataclass
class RuleSet:
    """Parsed rules file."""

    exclude: tuple[str, ...]
    rules: list[Rule]


@dataclass
class RuleResult:
    """Files changed by one rule."""

    rule: Rule
    files: list[str] = field(default_factory=list)
    substitutions: int = 0


@dataclass
class Report:
    """Outcome of a run over a tree."""

    results: dict[str, RuleResult]
    changed_files: list[str]

    def stale_rules(self) -> list[str]:
        """Return required rules that matched nothing."""
        return [
            rule_id
            for rule_id, result in self.results.items()
            if not result.rule.optional and not result.files
        ]


def _render(template: str, brand: Brand) -> str:
    return template.format(**vars(brand))


def load_rules(path: Path, brand: Brand) -> RuleSet:
    """Parse the TOML rules file.

    Args:
        path: Rules file.
        brand: Brand used to render replacement templates.

    Returns:
        Ordered rule set.

    Raises:
        ValueError: When a rule is missing a field or references an unknown
            include alias.
    """
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    defaults = data.get("defaults", {})
    aliases = {
        key: tuple(value)
        for key, value in defaults.items()
        if key != "exclude" and isinstance(value, list)
    }
    rules: list[Rule] = []
    for raw in data.get("rule", []):
        for key in ("id", "pattern", "replacement", "include"):
            if key not in raw:
                raise ValueError(f"rule missing '{key}': {raw}")
        include = raw["include"]
        if isinstance(include, str):
            if include not in aliases:
                raise ValueError(f"rule {raw['id']}: unknown include alias {include}")
            include = aliases[include]
        rules.append(
            Rule(
                id=raw["id"],
                pattern=re.compile(raw["pattern"]),
                replacement=_render(raw["replacement"], brand),
                include=tuple(include),
                optional=bool(raw.get("optional", False)),
            )
        )
    return RuleSet(exclude=tuple(defaults.get("exclude", [])), rules=rules)


def iter_files(root: Path):
    """Yield files under ``root`` while skipping heavyweight directories."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for filename in filenames:
            yield Path(dirpath) / filename


def rules_for(relative: str, rules: RuleSet) -> list[Rule]:
    """Return the rules that apply to one repository-relative path.

    Args:
        relative: POSIX path relative to the tree root.
        rules: Parsed rules.

    Returns:
        Applicable rules in order; empty when the path is excluded.
    """
    if matches_any(relative, rules.exclude):
        return []
    return [rule for rule in rules.rules if matches_any(relative, rule.include)]


def transform_text(text: str, applicable: list[Rule]) -> tuple[str, dict[str, int]]:
    """Run rules over one text.

    Args:
        text: File contents.
        applicable: Rules to apply, in order.

    Returns:
        The new text and the substitution count per rule id.
    """
    counts: dict[str, int] = {}
    for rule in applicable:
        text, count = rule.pattern.subn(rule.replacement, text)
        if count:
            counts[rule.id] = count
    return text, counts


def run(root: Path, rules: RuleSet, apply: bool) -> Report:
    """Apply or simulate the rules on every eligible file.

    Args:
        root: Tree to scan.
        rules: Parsed rules.
        apply: Write changes when True.

    Returns:
        Per-rule report.
    """
    results = {rule.id: RuleResult(rule=rule) for rule in rules.rules}
    changed_files: list[str] = []
    for path in iter_files(root):
        relative = to_posix(path, root)
        applicable = rules_for(relative, rules)
        if not applicable:
            continue
        original = read_text(path)
        if original is None:
            continue
        text, counts = transform_text(original, applicable)
        for rule_id, count in counts.items():
            results[rule_id].files.append(relative)
            results[rule_id].substitutions += count
        if text != original:
            changed_files.append(relative)
            if apply:
                path.write_text(text, encoding="utf-8", newline="")
    return Report(results=results, changed_files=changed_files)


def format_report(report: Report, verbose: bool) -> str:
    """Render the report as text.

    Args:
        report: Run outcome.
        verbose: Include file paths per rule.

    Returns:
        Multi-line string.
    """
    lines = []
    for rule_id, result in report.results.items():
        flag = " (optional)" if result.rule.optional else ""
        lines.append(
            f"{rule_id}{flag}: {len(result.files)} files, {result.substitutions} substitutions"
        )
        if verbose:
            lines.extend(f"  {path}" for path in sorted(set(result.files)))
    lines.append(f"files changed: {len(report.changed_files)}")
    stale = report.stale_rules()
    if stale:
        lines.append("stale rules (no matches): " + ", ".join(stale))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point.

    Args:
        argv: Arguments without the program name.

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check", action="store_true", help="dry run, fail on stale rules"
    )
    mode.add_argument(
        "--report", action="store_true", help="dry run, list files per rule"
    )
    mode.add_argument("--apply", action="store_true", help="rewrite files in place")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="tree to process")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument(
        "--allow-git-tree",
        action="store_true",
        help="permit --apply inside a directory that contains .git",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    if args.apply and (root / ".git").exists() and not args.allow_git_tree:
        print(
            f"refusing to rewrite git work tree {root}; copy it first or pass --allow-git-tree",
            file=sys.stderr,
        )
        return 2

    rules = load_rules(args.rules, load_brand())
    report = run(root, rules, apply=args.apply)
    print(format_report(report, verbose=args.report))
    if report.stale_rules():
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
