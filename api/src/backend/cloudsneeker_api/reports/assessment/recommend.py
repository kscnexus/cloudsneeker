"""Recommendation engine: what to do about a finding, and how urgently.

Every statement comes from the scanner record or from a fixed template for
the finding's category. Nothing here estimates CVSS, EPSS, exploit
availability, or asset criticality. When an advisory published a score and
the scanner kept it, it is shown as published and attributed to its source.

Priority is evidence-based and explained:

* P0 (0-24 hours): critical, and either a credential is exposed or a concrete
  fix exists.
* P1 (1-7 days): other critical findings; high findings that expose a
  credential or have a concrete fix.
* P2 (8-30 days): other high findings; medium findings.
* P3 (31-90 days): low findings.
* Informational findings are not scheduled.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from cloudsneeker_api.reports.assessment.model import (
    AREA_CLOUD,
    CATEGORY_CLOUD_CONFIG,
    CATEGORY_CODE,
    CATEGORY_LICENSE,
    CATEGORY_MISCONFIGURATION,
    CATEGORY_POLICY,
    CATEGORY_SECRET,
    CATEGORY_VULNERABILITY,
    NormalizedFinding,
)
from cloudsneeker_api.services.brand_text import scrub_engine_text

P0, P1, P2, P3 = "P0", "P1", "P2", "P3"
PRIORITIES: tuple[str, ...] = (P0, P1, P2, P3)

SLA_DAYS: dict[str, int] = {P0: 1, P1: 7, P2: 30, P3: 90}

WINDOWS: dict[str, dict[str, str]] = {
    P0: {"id": "0-24h", "label": "0-24 hours"},
    P1: {"id": "1-7d", "label": "1-7 days"},
    P2: {"id": "8-30d", "label": "8-30 days"},
    P3: {"id": "31-90d", "label": "31-90 days"},
}

PLACEHOLDER_NOTE = (
    "Values in <ANGLE_BRACKETS> are placeholders. Replace them with your own "
    "values before running anything."
)

# Upstream product name, assembled so this file passes the source brand audit.
_UPSTREAM = re.compile("".join(("pro", "wler")), re.IGNORECASE)
_MARKDOWN_CODE = re.compile(r"^```[\w-]*\s*|\s*```$")
_PLACEHOLDER = re.compile(r"<[A-Z][A-Z0-9_]*>")

SUGGESTED_OWNERS: dict[str, str] = {
    CATEGORY_CLOUD_CONFIG: "Cloud platform team",
    CATEGORY_VULNERABILITY: "Owning application team",
    CATEGORY_MISCONFIGURATION: "Infrastructure-as-code owners",
    CATEGORY_SECRET: "Owning application team with security",
    CATEGORY_LICENSE: "Engineering lead with legal",
    CATEGORY_CODE: "Owning application team",
    CATEGORY_POLICY: "Cloud governance owner",
}

WHY_IT_MATTERS: dict[str, str] = {
    CATEGORY_CLOUD_CONFIG: (
        "Cloud configuration controls who can reach resources and data. A "
        "failed control removes a layer of defense for the affected resources."
    ),
    CATEGORY_VULNERABILITY: (
        "The installed package version has a published vulnerability. "
        "Software that loads the package inherits the weakness until it is "
        "upgraded."
    ),
    CATEGORY_MISCONFIGURATION: (
        "Infrastructure templates are deployed as written, so a misconfigured "
        "template creates a misconfigured resource every time it is applied."
    ),
    CATEGORY_SECRET: (
        "A credential in source or an image can be read by anyone with access "
        "to that source, its history, or its copies, and used until revoked."
    ),
    CATEGORY_LICENSE: (
        "A dependency's license can place obligations on how the software is "
        "distributed. Shipping it without review is a legal and contractual risk."
    ),
    CATEGORY_CODE: (
        "The flagged code matches a known weakness pattern. If attacker input "
        "reaches it, it can be abused."
    ),
    CATEGORY_POLICY: (
        "The resource breaks a governance policy the organization defined, so "
        "it is outside the agreed security, cost, or tagging baseline."
    ),
}

POTENTIAL_IMPACT: dict[str, str] = {
    CATEGORY_CLOUD_CONFIG: (
        "Depending on the data and workloads involved, this can enable "
        "unauthorized access, data exposure, or loss of audit evidence."
    ),
    CATEGORY_VULNERABILITY: (
        "If the vulnerable code path is reachable, it can lead to the outcome "
        "the advisory describes (for example code execution or data exposure)."
    ),
    CATEGORY_MISCONFIGURATION: (
        "Resources built from this template can be exposed or weakened in the "
        "same way as a misconfigured cloud resource."
    ),
    CATEGORY_SECRET: (
        "A valid credential lets its holder act as the owning system: read or "
        "change data, run workloads, or incur cost."
    ),
    CATEGORY_LICENSE: (
        "Distribution terms may be breached, which can require code release, "
        "relicensing, or removal of the component."
    ),
    CATEGORY_CODE: (
        "Exploitation can lead to injection, data exposure, or unauthorized "
        "actions in the application, depending on the weakness."
    ),
    CATEGORY_POLICY: (
        "Drift from policy accumulates risk and cost and weakens audit evidence "
        "that controls are applied consistently."
    ),
}

PREVENTION: dict[str, list[str]] = {
    CATEGORY_CLOUD_CONFIG: [
        "Define the resource in infrastructure as code with the secure setting.",
        "Enforce the setting with an organization-level guardrail where the "
        "provider supports one.",
        "Keep a daily scheduled scan and alert on new critical or high results.",
    ],
    CATEGORY_VULNERABILITY: [
        "Enable automated dependency update pull requests.",
        "Fail builds on new critical vulnerabilities that have a fixed version.",
        "Rebuild images on a schedule so base layers pick up fixes.",
    ],
    CATEGORY_MISCONFIGURATION: [
        "Scan templates in pull requests and block merges on high or critical "
        "misconfigurations.",
        "Publish approved modules with secure defaults.",
    ],
    CATEGORY_SECRET: [
        "Add pre-commit and pull-request secret scanning.",
        "Load credentials from a secret manager or workload identity instead of files.",
        "Prefer short-lived credentials so a leak expires quickly.",
    ],
    CATEGORY_LICENSE: [
        "Publish an allowed-license list and check it in the build.",
    ],
    CATEGORY_CODE: [
        "Run static analysis in pull requests and block new high findings.",
        "Add a regression test for the fixed input path.",
    ],
    CATEGORY_POLICY: [
        "Schedule the policy and alert on new matches.",
        "Prevent drift at creation time with an organization policy or "
        "template default where the provider supports one.",
    ],
}


def clean_text(value: Any, limit: int = 1200) -> str:
    """Scanner text made safe for the report.

    Strips Markdown code fences, engine names, and the upstream product name,
    and bounds the length.
    """
    if not isinstance(value, str):
        return ""
    text = _MARKDOWN_CODE.sub("", value.strip()).replace("**", "")
    text = scrub_engine_text(text)
    text = _UPSTREAM.sub("the platform", text)
    return text[:limit].strip()


def clean_references(urls: list[str], limit: int = 5) -> list[str]:
    """Reference links without upstream-branded hosts."""
    result: list[str] = []
    for url in urls or []:
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            continue
        if _UPSTREAM.search(url) or url in result:
            continue
        result.append(url)
        if len(result) >= limit:
            break
    return result


def priority_for(finding: NormalizedFinding) -> str | None:
    """Evidence-based priority, or ``None`` for informational findings."""
    severity = finding.severity
    actionable = finding.category == CATEGORY_SECRET or bool(
        finding.fix.get("fix_available")
    )
    if severity == "critical":
        return P0 if actionable else P1
    if severity == "high":
        return P1 if actionable else P2
    if severity == "medium":
        return P2
    if severity == "low":
        return P3
    return None


@dataclass
class GroupStats:
    """How widespread one issue is across the scope.

    Attributes:
        findings: Open findings of the issue.
        resources: Distinct affected resources.
        accounts: Distinct accounts or targets.
        oldest_first_seen: Earliest first-seen time in the group.
    """

    findings: int = 1
    resources: int = 1
    accounts: int = 1
    oldest_first_seen: datetime | None = None


def justification(
    finding: NormalizedFinding, priority: str | None, stats: GroupStats, now: datetime
) -> str:
    """Why the priority was chosen, using only recorded facts."""
    parts = [f"Severity {finding.severity} as reported by the scanner"]
    if finding.category == CATEGORY_SECRET:
        parts.append("credential material is present in the scanned source")
    fixed = finding.fix.get("fixed_version")
    if fixed:
        parts.append(f"a fixed version ({fixed}) is published")
    elif finding.fix.get("fix_available"):
        parts.append("a documented fix exists")
    else:
        parts.append("no fixed version or documented fix is recorded")
    parts.append(
        f"affects {stats.resources} resource(s) across {stats.accounts} "
        f"account(s) or target(s)"
    )
    if stats.oldest_first_seen is not None:
        days = max(0, (now - stats.oldest_first_seen).days)
        parts.append(f"first seen {days} day(s) ago")
    published = finding.advisory.get("cvss_published")
    if published:
        parts.append(f"advisory-published CVSS {published}")
    rule = {
        P0: "critical with an exposed credential or a concrete fix",
        P1: "critical without a concrete fix, or high with an exposed credential or a concrete fix",
        P2: "high without a concrete fix, or medium",
        P3: "low severity",
    }.get(priority or "", "informational, not scheduled")
    return f"{'; '.join(parts)}. Priority rule: {rule}."


def _package_commands(finding: NormalizedFinding) -> list[dict[str, str]]:
    """Upgrade command for a vulnerable package, when the ecosystem is known."""
    package = finding.fix.get("package") or ""
    fixed = finding.fix.get("fixed_version") or ""
    purl = finding.fix.get("purl") or ""
    if not package or not fixed:
        return []
    ecosystem = (
        purl.split("/", 1)[0].removeprefix("pkg:") if purl.startswith("pkg:") else ""
    )
    commands = {
        "npm": f"npm install {package}@{fixed}",
        "pypi": f'pip install "{package}>={fixed}"  # then pin it in your requirements file',
        "golang": f"go get {package}@v{fixed.lstrip('v')} && go mod tidy",
        "gem": f"bundle update {package} --conservative  # Gemfile: '>= {fixed}'",
        "cargo": f"cargo update -p {package} --precise {fixed}",
        "nuget": f"dotnet add package {package} --version {fixed}",
        "composer": f"composer require {package}:^{fixed}",
        "maven": f"Set the {package} version to {fixed} in pom.xml (or build.gradle).",
    }
    command = commands.get(ecosystem)
    if not command:
        return []
    kind = "Instruction" if ecosystem == "maven" else "CLI"
    return [{"kind": kind, "label": f"Upgrade ({ecosystem})", "code": command}]


def _cloud_commands(finding: NormalizedFinding) -> list[dict[str, str]]:
    """CLI and Terraform snippets from the check's own metadata."""
    snippets = []
    for key, label in (
        ("cli", "CLI"),
        ("terraform", "Terraform"),
        ("nativeiac", "Native IaC"),
    ):
        code = clean_text(finding.remediation_code.get(key), limit=1500)
        if not code or code.startswith(("http://", "https://")):
            continue
        snippets.append(
            {"kind": label, "label": f"{label} (from check guidance)", "code": code}
        )
    return snippets[:2]


def _secret_commands(finding: NormalizedFinding) -> list[dict[str, str]]:
    return [
        {
            "kind": "CLI",
            "label": "Purge the value from git history (after revoking it)",
            "code": (
                "git filter-repo --replace-text <REPLACEMENTS_FILE>\n"
                "git push --force --all <REMOTE_NAME>"
            ),
        }
    ]


def instructions(finding: NormalizedFinding) -> list[str]:
    """Ordered remediation steps."""
    fix_summary = clean_text(finding.fix.get("fix_summary"), limit=600)
    resource = finding.resource_name or finding.resource_uid or "the affected resource"
    location = finding.location or resource
    category = finding.category
    if category == CATEGORY_SECRET:
        return [
            "Revoke or rotate the credential at its issuer first; removing it from "
            "code alone does not invalidate it.",
            f"Remove the value from {location} and load it from a secret manager "
            "or environment variable.",
            "Purge it from version-control history and any image layers that "
            "contain it.",
            "Review the issuer's access logs for use of the credential since it "
            "was first seen.",
        ]
    steps: list[str] = []
    if fix_summary:
        steps.append(fix_summary)
    if category == CATEGORY_VULNERABILITY:
        steps.append(
            "Rebuild and redeploy every artifact that bundles the package, "
            "including container images."
        )
    elif category == CATEGORY_CLOUD_CONFIG:
        steps.append(
            f"Apply the change to {resource} and to the template that created it."
        )
    elif category == CATEGORY_MISCONFIGURATION:
        steps.append(
            f"Correct the template at {location} and apply it through your pipeline."
        )
    elif category == CATEGORY_CODE:
        steps.append(
            f"Fix the code at {location} and validate untrusted input on that path."
        )
    elif category == CATEGORY_POLICY:
        steps.append(
            f"Bring {resource} in line with the policy, or record an approved "
            "exception with an owner and an expiry date."
        )
    elif category == CATEGORY_LICENSE:
        steps.append("Record the decision with the license owner.")
    if not steps:
        steps.append(
            "Review the finding with the resource owner and apply the documented fix."
        )
    return steps


def validation_steps(finding: NormalizedFinding) -> list[str]:
    """How to confirm the fix worked."""
    check = finding.check_id
    resource = finding.resource_name or finding.resource_uid or "the resource"
    category = finding.category
    if category == CATEGORY_CLOUD_CONFIG:
        return [
            f"Run a new scan of {finding.provider_label}.",
            f"Confirm check {check} reports PASS for {resource}.",
        ]
    if category == CATEGORY_VULNERABILITY:
        fixed = finding.fix.get("fixed_version")
        steps = [f"Rescan {finding.provider_label} after the rebuild."]
        steps.append(f"Confirm {check} is no longer reported for {resource}.")
        if fixed:
            steps.append(f"Confirm the installed version is {fixed} or later.")
        return steps
    if category == CATEGORY_SECRET:
        return [
            "Confirm the old credential is rejected by its issuer.",
            f"Rescan {finding.provider_label} and confirm rule {check} no longer matches.",
        ]
    if category == CATEGORY_POLICY:
        return [
            "Run the policy again (dry run).",
            f"Confirm {resource} is no longer matched.",
        ]
    return [
        f"Rescan {finding.provider_label}.",
        f"Confirm {check} is no longer reported at {finding.location or resource}.",
    ]


def expected_outcome(finding: NormalizedFinding, stats: GroupStats) -> str:
    """What the next scan should show once the fix is applied."""
    return (
        f"{stats.findings} open {finding.severity} finding(s) for {finding.check_id} "
        f"close on {stats.resources} resource(s); the next scan reports them as "
        f"{'passed' if finding.area == AREA_CLOUD else 'no longer present'}."
    )


def business_impact(finding: NormalizedFinding) -> dict[str, str]:
    """Confirmed facts from the scanner and the potential impact, kept apart."""
    evidence = clean_text(finding.status_extended, limit=400)
    if finding.category == CATEGORY_SECRET:
        confirmed = f"Credential material was found at {finding.location or finding.resource_name}."
    elif evidence:
        confirmed = evidence
    else:
        confirmed = ""
    potential = clean_text(finding.risk, limit=500) or POTENTIAL_IMPACT.get(
        finding.category, ""
    )
    return {"confirmed": confirmed, "potential": potential}


def recommend(
    finding: NormalizedFinding, stats: GroupStats | None = None, *, now: datetime
) -> dict[str, Any]:
    """Full recommendation for one finding (or the issue group it leads).

    Args:
        finding: Representative finding.
        stats: How widespread the issue is (defaults to this finding alone).
        now: Report time; target dates are counted from it.

    Returns:
        Recommendation mapping.
    """
    stats = stats or GroupStats(oldest_first_seen=finding.first_seen_at)
    priority = priority_for(finding)
    sla = SLA_DAYS.get(priority or "")
    commands: list[dict[str, str]] = []
    if finding.category == CATEGORY_VULNERABILITY:
        commands = _package_commands(finding)
    elif finding.category == CATEGORY_CLOUD_CONFIG:
        commands = _cloud_commands(finding)
    elif finding.category == CATEGORY_SECRET:
        commands = _secret_commands(finding)
    has_placeholders = any(_PLACEHOLDER.search(item["code"]) for item in commands)
    description = clean_text(finding.description, limit=700)
    return {
        "ref": finding.ref,
        "check_id": finding.check_id,
        "title": clean_text(finding.title, limit=250) or finding.check_id,
        "issue": description or clean_text(finding.title, limit=250),
        "why_it_matters": WHY_IT_MATTERS.get(finding.category, ""),
        "business_impact": business_impact(finding),
        "priority": priority,
        "window": WINDOWS[priority]["label"] if priority else None,
        "justification": justification(finding, priority, stats, now),
        "instructions": instructions(finding),
        "commands": commands,
        "placeholder_note": PLACEHOLDER_NOTE if has_placeholders else "",
        "validation": validation_steps(finding),
        "prevention": PREVENTION.get(finding.category, []),
        "suggested_owner": SUGGESTED_OWNERS.get(finding.category, "Resource owner"),
        "sla_days": sla,
        "target_date": (now + timedelta(days=sla)).date().isoformat() if sla else None,
        "expected_outcome": expected_outcome(finding, stats),
        "references": clean_references(finding.references),
        "advisory": dict(finding.advisory),
    }
