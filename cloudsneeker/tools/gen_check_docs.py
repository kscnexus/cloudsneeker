"""Generate the ``/checks/{check_id}`` reference pages for the product docs.

Usage::

    python cloudsneeker/tools/gen_check_docs.py [--providers-dir DIR] [--docs-dir DIR]

Reads every ``*.metadata.json`` under ``prowler/providers`` and writes one MDX
page per check into ``cloudsneeker/docs/checks/`` plus an index page, then
rewrites the ``Checks`` tab of ``cloudsneeker/docs/docs.json``. Finding
outputs link to ``{docs_url}/checks/{check_id}``, so this is what makes those
links resolve. Generated pages are not committed; the docs build runs this
first.
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent.parent
DEFAULT_PROVIDERS_DIR = REPO_ROOT / "prowler" / "providers"
DEFAULT_COMPLIANCE_DIR = REPO_ROOT / "prowler" / "compliance"
DEFAULT_DOCS_DIR = REPO_ROOT / "cloudsneeker" / "docs"
CHECKS_TAB = "Checks"
FRAMEWORKS_TAB = "Frameworks"

CLOUDFORMATION_TEMPLATE = "permissions/templates/cloudformation/prowler-scan-role.yml"
REBRAND_RULES = TOOLS_DIR / "rebrand.rules.toml"

sys.path.insert(0, str(REPO_ROOT))

from cloudsneeker.brand import Brand, load_brand  # noqa: E402
from cloudsneeker.tools.rebrand import (  # noqa: E402
    load_rules,
    rules_for,
    transform_text,
)

PROVIDER_LABELS = {
    "alibabacloud": "Alibaba Cloud",
    "aws": "AWS",
    "azure": "Azure",
    "cloudflare": "Cloudflare",
    "e2enetworks": "E2E Networks",
    "gcp": "Google Cloud",
    "github": "GitHub",
    "googleworkspace": "Google Workspace",
    "huaweicloud": "Huawei Cloud",
    "iac": "Infrastructure as Code",
    "kubernetes": "Kubernetes",
    "linode": "Linode",
    "llm": "LLM",
    "m365": "Microsoft 365",
    "mongodbatlas": "MongoDB Atlas",
    "nhn": "NHN Cloud",
    "okta": "Okta",
    "openstack": "OpenStack",
    "oraclecloud": "Oracle Cloud",
    "scaleway": "Scaleway",
    "stackit": "STACKIT",
    "vercel": "Vercel",
    "universal": "Cross-provider",
}
CODE_LANGUAGES = (
    ("CLI", "shell", "Command line"),
    ("Terraform", "hcl", "Terraform"),
    ("NativeIaC", "yaml", "Native IaC"),
    ("Other", "text", "Console"),
)
_UPSTREAM_NAME = re.compile(r"\bProwler\b")
_UPSTREAM_HUB_URL = re.compile(r"https?://hub\.prowler\.com/check/([A-Za-z0-9_.-]+)")
_FENCED = re.compile(r"^```")


@dataclass(frozen=True)
class Check:
    """Fields of one check that the page renders."""

    provider: str
    check_id: str
    title: str
    service: str
    severity: str
    resource_type: str
    description: str
    risk: str
    related_url: str
    additional_urls: tuple[str, ...]
    recommendation_text: str
    recommendation_url: str
    code: dict[str, str] = field(default_factory=dict)
    categories: tuple[str, ...] = ()


def _check_from_metadata(data: dict) -> Check:
    remediation = data.get("Remediation") or {}
    recommendation = remediation.get("Recommendation") or {}
    return Check(
        provider=data["Provider"],
        check_id=data["CheckID"],
        title=data.get("CheckTitle") or data["CheckID"],
        service=data.get("ServiceName") or "",
        severity=data.get("Severity") or "",
        resource_type=data.get("ResourceType") or "",
        description=data.get("Description") or "",
        risk=data.get("Risk") or "",
        related_url=data.get("RelatedUrl") or "",
        additional_urls=tuple(data.get("AdditionalURLs") or ()),
        recommendation_text=recommendation.get("Text") or "",
        recommendation_url=recommendation.get("Url") or "",
        code={k: v for k, v in (remediation.get("Code") or {}).items() if v},
        categories=tuple(data.get("Categories") or ()),
    )


def load_checks_from(records: list[dict]) -> list[Check]:
    """Build checks from parsed metadata records.

    Args:
        records: Parsed ``*.metadata.json`` contents.

    Returns:
        Checks sorted by provider and id.

    Raises:
        ValueError: When one provider has two records with the same ``CheckID``.
    """
    checks = sorted(
        (_check_from_metadata(r) for r in records),
        key=lambda c: (c.provider, c.check_id),
    )
    seen: set[tuple[str, str]] = set()
    for check in checks:
        key = (check.provider, check.check_id)
        if key in seen:
            raise ValueError(f"duplicate check id {check.check_id} in {check.provider}")
        seen.add(key)
    return checks


def group_by_id(checks: list[Check]) -> dict[str, list[Check]]:
    """Group checks that share an id across providers.

    A finding only carries the check id, so ``/checks/{check_id}`` is one page
    with a section per provider when ids collide.

    Args:
        checks: Checks sorted by provider and id.

    Returns:
        Mapping of check id to its provider variants, in provider order.
    """
    pages: dict[str, list[Check]] = {}
    for check in checks:
        pages.setdefault(check.check_id, []).append(check)
    return pages


def load_checks(providers_dir: Path) -> list[Check]:
    """Read every check metadata file under a providers directory.

    Args:
        providers_dir: Root such as ``prowler/providers``.

    Returns:
        Checks sorted by provider and id.
    """
    records = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(providers_dir.glob("*/services/*/*/*.metadata.json"))
    ]
    return load_checks_from(records)


def _brand_text(text: str, brand: Brand) -> str:
    text = _UPSTREAM_HUB_URL.sub(lambda m: brand.check_docs_url(m.group(1)), text)
    return _UPSTREAM_NAME.sub(brand.name, text)


def _escape_mdx(text: str) -> str:
    """Escape characters MDX would parse as JSX outside fenced code."""
    out: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if _FENCED.match(line):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            continue
        out.append(line.replace("{", "\\{").replace("}", "\\}").replace("<", "\\<"))
    return "\n".join(out)


def _yaml_string(value: str) -> str:
    return json.dumps(value)


def _code_block(key: str, language: str, label: str, snippet: str) -> str:
    body = snippet.strip()
    if not body.startswith("```"):
        body = f"```{language}\n{body}\n```"
    return f"### {label}\n\n{body}\n"


def _render_section(check: Check, brand: Brand, heading_level: int) -> list[str]:
    text = lambda s: _escape_mdx(_brand_text(s, brand))  # noqa: E731
    h = "#" * heading_level
    provider_label = PROVIDER_LABELS.get(check.provider, check.provider)
    lines = [
        f"**Provider:** {provider_label} · **Service:** `{check.service}` · "
        f"**Severity:** `{check.severity}` · **Resource type:** `{check.resource_type}`",
        "",
    ]
    if check.categories:
        lines += [
            "**Categories:** " + ", ".join(f"`{c}`" for c in check.categories),
            "",
        ]
    lines += [f"{h} Description", "", text(check.description), ""]
    if check.risk:
        lines += [f"{h} Risk", "", text(check.risk), ""]
    lines += [f"{h} Remediation", ""]
    if check.recommendation_text:
        lines += [text(check.recommendation_text), ""]
    for key, language, label in CODE_LANGUAGES:
        snippet = check.code.get(key)
        if snippet:
            block = _code_block(key, language, label, _brand_text(snippet, brand))
            lines += [block.replace("### ", f"{h}# ", 1), ""]
    links = [u for u in (check.related_url, *check.additional_urls) if u]
    if check.recommendation_url and not _UPSTREAM_HUB_URL.match(
        check.recommendation_url
    ):
        links.insert(0, check.recommendation_url)
    if links:
        lines += [f"{h} References", ""]
        lines += [f"- [{u}]({u})" for u in dict.fromkeys(links)]
        lines += [""]
    return lines


def render_page(variants: list[Check], brand: Brand) -> str:
    """Render one check id as an MDX page.

    Args:
        variants: The check as implemented by each provider; at least one.
        brand: Product identity used for names and links.

    Returns:
        MDX source. With several providers each gets its own top-level
        section.
    """
    first = variants[0]
    providers = " / ".join(
        PROVIDER_LABELS.get(c.provider, c.provider) for c in variants
    )
    description = (
        f"{providers} / {first.service} / {first.severity}"
        if len(variants) == 1
        else f"{providers} / {first.check_id}"
    )
    lines = [
        "---",
        f"title: {_yaml_string(_brand_text(first.title, brand))}",
        f"description: {_yaml_string(description)}",
        "---",
        "",
    ]
    if len(variants) == 1:
        lines += _render_section(first, brand, heading_level=2)
    else:
        for check in variants:
            lines += [f"## {PROVIDER_LABELS.get(check.provider, check.provider)}", ""]
            lines += _render_section(check, brand, heading_level=3)
    return "\n".join(lines)


def render_index(checks: list[Check], brand: Brand) -> str:
    """Render the checks index page.

    Args:
        checks: All checks.
        brand: Product identity.

    Returns:
        MDX source.
    """
    lines = [
        "---",
        'title: "Security checks"',
        f'description: "Every check {brand.name} can run, grouped by provider"',
        "---",
        "",
        f"{brand.name} ships {len(checks)} checks. Each finding links to its page here.",
        "",
    ]
    current = None
    for check in checks:
        if check.provider != current:
            current = check.provider
            lines += [f"## {PROVIDER_LABELS.get(current, current)}", ""]
        lines.append(
            f"- [{_brand_text(check.title, brand)}](/checks/{check.check_id}) "
            f"(`{check.service}`, {check.severity})"
        )
    lines.append("")
    return "\n".join(lines)


def _navigation_groups(checks: list[Check]) -> list[dict]:
    groups: list[dict] = [{"group": "Overview", "pages": ["checks/index"]}]
    by_provider: dict[str, dict[str, list[str]]] = {}
    listed: set[str] = set()
    for check in checks:
        # A shared id has one page; list it under the first provider only.
        if check.check_id in listed:
            continue
        listed.add(check.check_id)
        by_provider.setdefault(check.provider, {}).setdefault(check.service, []).append(
            f"checks/{check.check_id}"
        )
    for provider, services in by_provider.items():
        groups.append(
            {
                "group": PROVIDER_LABELS.get(provider, provider),
                "pages": [
                    {"group": service, "pages": pages}
                    for service, pages in sorted(services.items())
                ],
            }
        )
    return groups


def _update_navigation(docs_json: Path, tab_name: str, groups: list[dict]) -> None:
    data = json.loads(docs_json.read_text(encoding="utf-8"))
    tabs = data["navigation"]["tabs"]
    for tab in tabs:
        if tab.get("tab") == tab_name:
            tab["groups"] = groups
            break
    else:
        tabs.append({"tab": tab_name, "groups": groups})
    docs_json.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def write_docs(providers_dir: Path, docs_dir: Path, brand: Brand) -> list[Path]:
    """Write check pages, the index, and the navigation.

    Args:
        providers_dir: Root of the provider packages.
        docs_dir: Mintlify docs root containing ``docs.json``.
        brand: Product identity.

    Returns:
        Paths written.
    """
    checks = load_checks(providers_dir)
    checks_dir = docs_dir / "checks"
    checks_dir.mkdir(parents=True, exist_ok=True)
    for stale in checks_dir.glob("*.mdx"):
        stale.unlink()
    written: list[Path] = []
    for check_id, variants in group_by_id(checks).items():
        path = checks_dir / f"{check_id}.mdx"
        path.write_text(render_page(variants, brand), encoding="utf-8", newline="\n")
        written.append(path)
    index = checks_dir / "index.mdx"
    index.write_text(render_index(checks, brand), encoding="utf-8", newline="\n")
    written.append(index)
    _update_navigation(docs_dir / "docs.json", CHECKS_TAB, _navigation_groups(checks))
    return written


@dataclass(frozen=True)
class Requirement:
    """One requirement of a compliance framework."""

    requirement_id: str
    description: str
    checks: tuple[str, ...]
    section: str


@dataclass(frozen=True)
class Framework:
    """One compliance framework file."""

    provider: str
    framework_id: str
    name: str
    framework: str
    version: str
    description: str
    requirements: tuple[Requirement, ...]


UNIVERSAL_PROVIDER = "universal"
SECTION_KEYS = ("Section", "Category", "Domain", "Function")


def _section_from(attributes: object) -> str:
    first = attributes[0] if isinstance(attributes, list) and attributes else attributes
    if not isinstance(first, dict):
        return ""
    for key in SECTION_KEYS:
        if first.get(key):
            return str(first[key])
    return ""


def _requirement_from(data: dict) -> Requirement:
    """Accept both the per-provider schema (``Id``/``Checks``) and the
    universal schema (``id``/``checks`` keyed by provider)."""
    if "Id" in data:
        return Requirement(
            requirement_id=str(data.get("Id", "")),
            description=data.get("Description") or "",
            checks=tuple(data.get("Checks") or ()),
            section=_section_from(data.get("Attributes")),
        )
    raw_checks = data.get("checks") or {}
    checks = (
        tuple(dict.fromkeys(c for cs in raw_checks.values() for c in cs))
        if isinstance(raw_checks, dict)
        else tuple(raw_checks)
    )
    return Requirement(
        requirement_id=str(data.get("id", "")),
        description=data.get("name") or data.get("description") or "",
        checks=checks,
        section=_section_from(data.get("attributes")),
    )


def _framework_from(provider: str, stem: str, data: dict) -> Framework:
    get = lambda key: data.get(key) or data.get(key.lower()) or ""  # noqa: E731
    return Framework(
        provider=provider,
        framework_id=stem,
        name=get("Name") or stem,
        framework=get("Framework"),
        version=str(get("Version")),
        description=get("Description"),
        requirements=tuple(_requirement_from(r) for r in get("Requirements") or ()),
    )


def load_frameworks_from(records: list[tuple[str, str, dict]]) -> list[Framework]:
    """Build frameworks from parsed compliance files.

    Args:
        records: ``(provider, file stem, parsed json)`` triples. Use
            ``"universal"`` as the provider for cross-provider frameworks.

    Returns:
        Frameworks sorted by provider and id.
    """
    frameworks = [_framework_from(p, s, d) for p, s, d in records]
    return sorted(frameworks, key=lambda f: (f.provider, f.framework_id))


def load_frameworks(compliance_dir: Path) -> list[Framework]:
    """Read every compliance framework under ``prowler/compliance``.

    Per-provider files live in ``<provider>/<id>.json``; cross-provider
    files sit directly in the root.

    Args:
        compliance_dir: Root of the compliance catalog.

    Returns:
        Frameworks sorted by provider and id.
    """
    records = [
        (path.parent.name, path.stem, json.loads(path.read_text(encoding="utf-8")))
        for path in sorted(compliance_dir.glob("*/*.json"))
    ] + [
        (UNIVERSAL_PROVIDER, path.stem, json.loads(path.read_text(encoding="utf-8")))
        for path in sorted(compliance_dir.glob("*.json"))
    ]
    return load_frameworks_from(records)


def render_framework_page(framework: Framework, brand: Brand) -> str:
    """Render one compliance framework as an MDX page.

    Args:
        framework: Framework to render.
        brand: Product identity.

    Returns:
        MDX source listing every requirement and its checks.
    """
    text = lambda s: _escape_mdx(_brand_text(s, brand))  # noqa: E731
    provider_label = PROVIDER_LABELS.get(framework.provider, framework.provider)
    automated = sum(1 for r in framework.requirements if r.checks)
    lines = [
        "---",
        f"title: {_yaml_string(_brand_text(framework.name, brand))}",
        f"description: {_yaml_string(f'{provider_label} / {framework.framework} {framework.version}'.strip())}",
        "---",
        "",
        f"**Provider:** {provider_label} · **Framework:** {framework.framework} · "
        f"**Version:** {framework.version or '—'} · **Requirements:** {len(framework.requirements)} "
        f"({automated} automated)",
        "",
    ]
    if framework.description:
        lines += [text(framework.description), ""]
    lines += ["## Requirements", ""]
    current_section = None
    for requirement in framework.requirements:
        if requirement.section != current_section:
            current_section = requirement.section
            if current_section:
                lines += [f"### {text(current_section)}", ""]
        checks = (
            ", ".join(f"[`{c}`](/checks/{c})" for c in requirement.checks)
            if requirement.checks
            else "_manual_"
        )
        lines.append(
            f"- **{text(requirement.requirement_id)}** {text(requirement.description)} — {checks}"
        )
    lines.append("")
    return "\n".join(lines)


def render_framework_index(frameworks: list[Framework], brand: Brand) -> str:
    """Render the compliance frameworks index page.

    Args:
        frameworks: All frameworks.
        brand: Product identity.

    Returns:
        MDX source.
    """
    lines = [
        "---",
        'title: "Compliance frameworks"',
        f'description: "Every framework {brand.name} scores, grouped by provider"',
        "---",
        "",
        f"{brand.name} maps its checks to {len(frameworks)} framework versions. "
        "Each page lists the requirements and the checks behind them.",
        "",
    ]
    current = None
    for framework in frameworks:
        if framework.provider != current:
            current = framework.provider
            lines += [f"## {PROVIDER_LABELS.get(current, current)}", ""]
        lines.append(
            f"- [{_brand_text(framework.name, brand)}](/compliance/{framework.framework_id}) "
            f"({len(framework.requirements)} requirements)"
        )
    lines.append("")
    return "\n".join(lines)


def _framework_navigation_groups(frameworks: list[Framework]) -> list[dict]:
    groups: list[dict] = [{"group": "Overview", "pages": ["compliance/index"]}]
    by_provider: dict[str, list[str]] = {}
    for framework in frameworks:
        by_provider.setdefault(framework.provider, []).append(
            f"compliance/{framework.framework_id}"
        )
    for provider, pages in by_provider.items():
        groups.append(
            {"group": PROVIDER_LABELS.get(provider, provider), "pages": pages}
        )
    return groups


def write_compliance_docs(
    compliance_dir: Path, docs_dir: Path, brand: Brand
) -> list[Path]:
    """Write one page per compliance framework plus the index and navigation.

    The web app links a framework as ``{docs_url}/compliance/{framework_id}``.

    Args:
        compliance_dir: Root of the compliance catalog.
        docs_dir: Mintlify docs root containing ``docs.json``.
        brand: Product identity.

    Returns:
        Paths written.
    """
    frameworks = load_frameworks(compliance_dir)
    target_dir = docs_dir / "compliance"
    target_dir.mkdir(parents=True, exist_ok=True)
    for stale in target_dir.glob("*.mdx"):
        stale.unlink()
    written: list[Path] = []
    for framework in frameworks:
        path = target_dir / f"{framework.framework_id}.mdx"
        path.write_text(
            render_framework_page(framework, brand), encoding="utf-8", newline="\n"
        )
        written.append(path)
    index = target_dir / "index.mdx"
    index.write_text(
        render_framework_index(frameworks, brand), encoding="utf-8", newline="\n"
    )
    written.append(index)
    _update_navigation(
        docs_dir / "docs.json", FRAMEWORKS_TAB, _framework_navigation_groups(frameworks)
    )
    return written


def template_file_name(brand: Brand) -> str:
    """Return the published file name of the AWS scan-role template.

    Args:
        brand: Product identity.

    Returns:
        ``"<slug>-scan-role.yml"``; the last segment of
        ``brand.cloudformation_template_url``.
    """
    return f"{brand.slug}-scan-role.yml"


def write_templates(repo_root: Path, docs_dir: Path, brand: Brand) -> list[Path]:
    """Publish the AWS CloudFormation template under ``docs/templates``.

    The web app's quick-create link points at
    ``brand.cloudformation_template_url``, which this file serves. The source
    template is run through the same rebrand rules as the build tree.

    Args:
        repo_root: Repository root containing ``permissions/``.
        docs_dir: Mintlify docs root.
        brand: Product identity.

    Returns:
        Paths written; empty when the source template does not exist.
    """
    source = repo_root / CLOUDFORMATION_TEMPLATE
    if not source.exists():
        return []
    rules = load_rules(REBRAND_RULES, brand)
    text, _ = transform_text(
        source.read_text(encoding="utf-8"), rules_for(CLOUDFORMATION_TEMPLATE, rules)
    )
    target = docs_dir / "templates" / template_file_name(brand)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")
    return [target]


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point.

    Args:
        argv: Arguments without the program name.

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--providers-dir", type=Path, default=DEFAULT_PROVIDERS_DIR)
    parser.add_argument("--compliance-dir", type=Path, default=DEFAULT_COMPLIANCE_DIR)
    parser.add_argument("--docs-dir", type=Path, default=DEFAULT_DOCS_DIR)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    brand = load_brand()
    docs_dir = args.docs_dir.resolve()
    written = write_docs(args.providers_dir.resolve(), docs_dir, brand)
    compliance_dir = args.compliance_dir.resolve()
    frameworks = (
        write_compliance_docs(compliance_dir, docs_dir, brand)
        if compliance_dir.exists()
        else []
    )
    templates = write_templates(args.repo_root.resolve(), docs_dir, brand)
    print(
        f"wrote {len(written) - 1} check pages, {max(len(frameworks) - 1, 0)} framework pages, "
        f"their indexes, and {len(templates)} template(s) to {args.docs_dir}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
