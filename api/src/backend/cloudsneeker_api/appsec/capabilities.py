"""What the scan engine can do, per target type.

Source of truth: the engine's CLI reference and Go types at the pinned
version (``ENGINE_VERSION``). The API serves this module so the UI offers
only valid target, scanner and option combinations, and
``knowledge-base/appsec-coverage.md`` is generated from ``FEATURES``.

Nothing here is inferred: an option is listed for a target only when the
command for that target accepts the flag at the pinned version.
"""

from __future__ import annotations

from typing import Any

ENGINE_NAME = "trivy"
# Pinned in ``api/Dockerfile`` (``TRIVY_VERSION``), checksum verified there.
ENGINE_VERSION = "0.74.0"
REPORT_SCHEMA_VERSION = 2

SCANNER_VULN = "vuln"
SCANNER_MISCONFIG = "misconfig"
SCANNER_SECRET = "secret"
SCANNER_LICENSE = "license"
SCANNER_RBAC = "rbac"

SCANNER_LABELS = {
    SCANNER_VULN: "Vulnerabilities",
    SCANNER_MISCONFIG: "Misconfigurations",
    SCANNER_SECRET: "Secrets",
    SCANNER_LICENSE: "Licenses",
    SCANNER_RBAC: "Kubernetes RBAC",
}

SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
IGNORE_STATUSES = (
    "unknown",
    "not_affected",
    "affected",
    "fixed",
    "under_investigation",
    "will_not_fix",
    "fix_deferred",
    "end_of_life",
)
PKG_TYPES = ("os", "library")
PKG_RELATIONSHIPS = ("unknown", "root", "workspace", "direct", "indirect")
DETECTION_PRIORITIES = ("precise", "comprehensive")
MISCONFIG_SCANNERS = (
    "azure-arm",
    "cloudformation",
    "dockerfile",
    "helm",
    "kubernetes",
    "terraform",
    "terraformplan-json",
    "terraformplan-snapshot",
    "ansible",
)
IMAGE_CONFIG_SCANNERS = (SCANNER_MISCONFIG, SCANNER_SECRET)
LICENSE_CATEGORIES = (
    "forbidden",
    "restricted",
    "reciprocal",
    "notice",
    "permissive",
    "unencumbered",
    "unknown",
)
# Severity the engine assigns to each license category.
LICENSE_CATEGORY_SEVERITY = {
    "forbidden": "critical",
    "restricted": "high",
    "reciprocal": "medium",
    "notice": "low",
    "permissive": "low",
    "unencumbered": "low",
    "unknown": "unknown",
}

# Options every scanning command accepts.
_COMMON_OPTIONS = (
    "severities",
    "ignore_unfixed",
    "ignore_statuses",
    "pkg_types",
    "pkg_relationships",
    "detection_priority",
    "timeout_seconds",
    "offline_scan",
)
_MISCONFIG_OPTIONS = (
    "misconfig_scanners",
    "include_non_failures",
    "include_deprecated_checks",
)
_PATH_OPTIONS = ("skip_dirs", "skip_files")
_FULL_LICENSE_OPTIONS = (
    "license_full",
    "license_confidence_level",
    "ignored_licenses",
)

# Target types, keyed by ``TrivyTarget.mode``.
TARGETS: dict[str, dict[str, Any]] = {
    "repo": {
        "label": "Code repository",
        "command": "repository",
        "experimental": False,
        "scanners": (SCANNER_VULN, SCANNER_MISCONFIG, SCANNER_SECRET, SCANNER_LICENSE),
        "default_scanners": (SCANNER_VULN, SCANNER_SECRET),
        "options": (
            *_COMMON_OPTIONS,
            *_MISCONFIG_OPTIONS,
            *_PATH_OPTIONS,
            *_FULL_LICENSE_OPTIONS,
            "include_dev_deps",
            "branch",
            "tag",
            "commit",
        ),
        "export_formats": ("json", "sarif", "cyclonedx", "spdx-json"),
        "notes": (
            "Reads lock files, not installed packages. Detects vulnerable "
            "dependencies, misconfigurations, secrets and licenses; it is not "
            "a semantic code analyzer (see Static analysis).",
            "SSH repositories are cloned first (branch or tag, not commit) and "
            "scanned as a directory; the branch is recorded, other Git "
            "metadata is not.",
        ),
    },
    "fs": {
        "label": "Filesystem (uploaded archive)",
        "command": "filesystem",
        "experimental": False,
        "scanners": (SCANNER_VULN, SCANNER_MISCONFIG, SCANNER_SECRET, SCANNER_LICENSE),
        "default_scanners": (SCANNER_VULN, SCANNER_SECRET),
        "options": (
            *_COMMON_OPTIONS,
            *_MISCONFIG_OPTIONS,
            *_PATH_OPTIONS,
            *_FULL_LICENSE_OPTIONS,
            "include_dev_deps",
        ),
        "export_formats": ("json", "sarif", "cyclonedx", "spdx-json"),
        "notes": (
            "Only an uploaded archive is scanned; a path on the worker is "
            "never accepted.",
        ),
    },
    "iac": {
        "label": "Infrastructure as Code repository",
        "command": "repository",
        "experimental": False,
        "scanners": (SCANNER_VULN, SCANNER_MISCONFIG, SCANNER_SECRET, SCANNER_LICENSE),
        "default_scanners": (SCANNER_MISCONFIG, SCANNER_SECRET, SCANNER_VULN),
        "options": (
            *_COMMON_OPTIONS,
            *_MISCONFIG_OPTIONS,
            *_PATH_OPTIONS,
            "ignored_licenses",
            "branch",
            "tag",
            "commit",
        ),
        "export_formats": ("json", "sarif", "cyclonedx", "spdx-json"),
        "notes": (
            "Terraform, Terraform plans, CloudFormation, Dockerfile, "
            "Kubernetes manifests, Helm, Azure ARM and Ansible.",
        ),
    },
    "rootfs": {
        "label": "Root filesystem (uploaded archive)",
        "command": "rootfs",
        "experimental": False,
        "scanners": (SCANNER_VULN, SCANNER_MISCONFIG, SCANNER_SECRET, SCANNER_LICENSE),
        "default_scanners": (SCANNER_VULN, SCANNER_SECRET),
        "options": (
            *_COMMON_OPTIONS,
            *_MISCONFIG_OPTIONS,
            *_PATH_OPTIONS,
            *_FULL_LICENSE_OPTIONS,
        ),
        "export_formats": ("json", "sarif", "cyclonedx", "spdx-json"),
        "notes": (
            "Reads installed-package metadata (OS package databases, wheels, "
            "gemspecs, JARs, binaries), like an image scan; lock files are "
            "not read.",
        ),
    },
    "image": {
        "label": "Container image",
        "command": "image",
        "experimental": False,
        "scanners": (SCANNER_VULN, SCANNER_MISCONFIG, SCANNER_SECRET, SCANNER_LICENSE),
        "default_scanners": (SCANNER_VULN, SCANNER_SECRET),
        "options": (
            *_COMMON_OPTIONS,
            *_MISCONFIG_OPTIONS,
            *_PATH_OPTIONS,
            *_FULL_LICENSE_OPTIONS,
            "image_config_scanners",
            "platform",
            "removed_pkgs",
        ),
        "export_formats": ("json", "sarif", "cyclonedx", "spdx-json"),
        "notes": (
            "Images are pulled from the registry (image source: remote); the "
            "worker has no container runtime socket.",
            "A source that is a whole registry is scanned image by image by "
            "the registry scan and has no component inventory yet.",
        ),
    },
    "sbom": {
        "label": "SBOM document",
        "command": "sbom",
        "experimental": False,
        "scanners": (SCANNER_VULN, SCANNER_LICENSE),
        "default_scanners": (SCANNER_VULN,),
        "options": (*_COMMON_OPTIONS, "ignored_licenses"),
        "export_formats": ("json", "sarif", "cyclonedx", "spdx-json"),
        "notes": (
            "Accepts CycloneDX JSON, SPDX JSON and SPDX tag-value. CycloneDX "
            "XML is not supported by the engine.",
            "Licenses are read from the document only; file-level license "
            "detection does not apply.",
        ),
    },
    "k8s": {
        "label": "Kubernetes cluster",
        "command": "kubernetes",
        "experimental": True,
        "scanners": (SCANNER_VULN, SCANNER_MISCONFIG, SCANNER_SECRET, SCANNER_RBAC),
        "default_scanners": (SCANNER_VULN, SCANNER_MISCONFIG, SCANNER_SECRET),
        "options": (
            *_COMMON_OPTIONS,
            *_MISCONFIG_OPTIONS,
            *_PATH_OPTIONS,
            "include_namespaces",
            "exclude_namespaces",
            "include_kinds",
            "exclude_kinds",
            "skip_images",
            "disable_node_collector",
        ),
        "export_formats": ("json",),
        "notes": (
            "The engine marks cluster scanning experimental. The license "
            "scanner is not available for this target.",
            "The node collector starts a job on every node; it is off unless "
            "a profile enables it.",
            "The cluster report cannot be converted to SARIF or SPDX.",
        ),
    },
}

# Target types the engine has but this deployment does not offer, and why.
UNAVAILABLE_TARGETS: dict[str, dict[str, str]] = {
    "vm": {
        "label": "Virtual machine image",
        "status": "missing",
        "reason": (
            "The engine (experimental) reads a local VMDK file or an AWS AMI "
            "or EBS snapshot. Disk images are too large for the upload path "
            "and the AWS form needs a per-tenant role with EBS direct API "
            "access; neither is built."
        ),
    },
    "config": {
        "label": "Configuration-only scan",
        "status": "not_applicable",
        "reason": (
            "Covered by the misconfiguration scanner on repository, "
            "filesystem and Infrastructure as Code targets."
        ),
    },
}

# Target types that run another engine.
OTHER_ENGINE_TARGETS = {
    "sast": {
        "label": "Static analysis (SAST)",
        "engine": "opengrep",
        "category": "code",
    }
}

OPTION_SPECS: dict[str, dict[str, Any]] = {
    "severities": {
        "type": "choices",
        "choices": SEVERITIES,
        "flag": "--severity",
        "label": "Severities to report",
        "help": "Findings below the selection are not reported by the scan.",
    },
    "ignore_unfixed": {
        "type": "bool",
        "flag": "--ignore-unfixed",
        "label": "Only vulnerabilities with a fix",
        "scanner": SCANNER_VULN,
    },
    "ignore_statuses": {
        "type": "choices",
        "choices": IGNORE_STATUSES,
        "flag": "--ignore-status",
        "label": "Vulnerability statuses to drop",
        "scanner": SCANNER_VULN,
    },
    "pkg_types": {
        "type": "choices",
        "choices": PKG_TYPES,
        "flag": "--pkg-types",
        "label": "Package types",
        "help": "os: operating system packages. library: language packages.",
    },
    "pkg_relationships": {
        "type": "choices",
        "choices": PKG_RELATIONSHIPS,
        "flag": "--pkg-relationships",
        "label": "Dependency relationships",
        "help": "Cannot be combined with VEX documents; it is dropped when "
        "an enabled VEX document applies.",
    },
    "detection_priority": {
        "type": "choice",
        "choices": DETECTION_PRIORITIES,
        "flag": "--detection-priority",
        "label": "Detection priority",
        "help": "precise: fewer false positives. comprehensive: more findings.",
    },
    "timeout_seconds": {
        "type": "int",
        "min": 60,
        "max": 7200,
        "flag": "--timeout",
        "label": "Scan timeout (seconds)",
    },
    "offline_scan": {
        "type": "bool",
        "flag": "--offline-scan",
        "label": "Do not call package registries to resolve dependencies",
    },
    "misconfig_scanners": {
        "type": "choices",
        "choices": MISCONFIG_SCANNERS,
        "flag": "--misconfig-scanners",
        "label": "Configuration formats",
        "scanner": SCANNER_MISCONFIG,
    },
    "include_non_failures": {
        "type": "bool",
        "flag": "--include-non-failures",
        "label": "Record passed checks",
        "scanner": SCANNER_MISCONFIG,
    },
    "include_deprecated_checks": {
        "type": "bool",
        "flag": "--include-deprecated-checks",
        "label": "Run deprecated checks",
        "scanner": SCANNER_MISCONFIG,
    },
    "skip_dirs": {
        "type": "globs",
        "flag": "--skip-dirs",
        "label": "Directories to skip",
    },
    "skip_files": {
        "type": "globs",
        "flag": "--skip-files",
        "label": "Files to skip",
    },
    "license_full": {
        "type": "bool",
        "flag": "--license-full",
        "label": "Read licenses from source headers and license files",
        "scanner": SCANNER_LICENSE,
    },
    "license_confidence_level": {
        "type": "float",
        "min": 0.0,
        "max": 1.0,
        "flag": "--license-confidence-level",
        "label": "License classifier confidence",
        "scanner": SCANNER_LICENSE,
    },
    "ignored_licenses": {
        "type": "strings",
        "flag": "--ignored-licenses",
        "label": "Licenses to leave out",
        "scanner": SCANNER_LICENSE,
    },
    "include_dev_deps": {
        "type": "bool",
        "flag": "--include-dev-deps",
        "label": "Include development dependencies",
        "help": "npm, yarn and gradle only.",
    },
    "image_config_scanners": {
        "type": "choices",
        "choices": IMAGE_CONFIG_SCANNERS,
        "flag": "--image-config-scanners",
        "label": "Scan the image configuration for",
    },
    "platform": {
        "type": "platform",
        "flag": "--platform",
        "label": "Platform (os/arch) of a multi-platform image",
    },
    "removed_pkgs": {
        "type": "bool",
        "flag": "--removed-pkgs",
        "label": "Detect vulnerabilities in removed packages (Alpine only)",
    },
    "branch": {"type": "ref", "flag": "--branch", "label": "Branch"},
    "tag": {"type": "ref", "flag": "--tag", "label": "Tag"},
    "commit": {"type": "ref", "flag": "--commit", "label": "Commit"},
    "include_namespaces": {
        "type": "k8s_names",
        "flag": "--include-namespaces",
        "label": "Namespaces to scan",
    },
    "exclude_namespaces": {
        "type": "k8s_names",
        "flag": "--exclude-namespaces",
        "label": "Namespaces to leave out",
    },
    "include_kinds": {
        "type": "k8s_names",
        "flag": "--include-kinds",
        "label": "Resource kinds to scan",
    },
    "exclude_kinds": {
        "type": "k8s_names",
        "flag": "--exclude-kinds",
        "label": "Resource kinds to leave out",
    },
    "skip_images": {
        "type": "bool",
        "flag": "--skip-images",
        "label": "Do not pull and scan workload images",
    },
    "disable_node_collector": {
        "type": "bool",
        "flag": "--disable-node-collector",
        "label": "Do not run the node collector job",
        "default": True,
    },
}

BUILTIN_PROFILE_PREFIX = "builtin:"

BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "balanced": {
        "name": "Balanced",
        "description": "Vulnerabilities, misconfigurations and secrets at "
        "every severity. The default.",
        "target_types": [],
        "options": {
            "scanners": [SCANNER_VULN, SCANNER_MISCONFIG, SCANNER_SECRET],
        },
    },
    "full": {
        "name": "Full assessment",
        "description": "Every scanner the target supports, including "
        "licenses, with comprehensive detection.",
        "target_types": [],
        "options": {
            "scanners": [
                SCANNER_VULN,
                SCANNER_MISCONFIG,
                SCANNER_SECRET,
                SCANNER_LICENSE,
                SCANNER_RBAC,
            ],
            "detection_priority": "comprehensive",
        },
    },
    "dependencies": {
        "name": "Dependencies and licenses",
        "description": "Software composition: vulnerable packages and "
        "license risk. No secrets or configuration checks.",
        "target_types": ["repo", "fs", "rootfs", "image", "sbom"],
        "options": {"scanners": [SCANNER_VULN, SCANNER_LICENSE]},
    },
    "secrets": {
        "name": "Secrets only",
        "description": "Credentials, tokens and keys in files and image layers.",
        "target_types": ["repo", "fs", "iac", "rootfs", "image"],
        "options": {"scanners": [SCANNER_SECRET]},
    },
    "iac": {
        "name": "Infrastructure as Code",
        "description": "Configuration checks for Terraform, CloudFormation, "
        "Kubernetes, Helm, Dockerfile, ARM and Ansible, plus secrets.",
        "target_types": ["repo", "fs", "iac"],
        "options": {"scanners": [SCANNER_MISCONFIG, SCANNER_SECRET]},
    },
    "release_gate": {
        "name": "Release gate",
        "description": "High and critical vulnerabilities that have a fix, "
        "and secrets. Short enough for every build.",
        "target_types": ["repo", "fs", "rootfs", "image"],
        "options": {
            "scanners": [SCANNER_VULN, SCANNER_SECRET],
            "severities": ["HIGH", "CRITICAL"],
            "ignore_unfixed": True,
        },
    },
}

DEFAULT_PROFILE_REF = f"{BUILTIN_PROFILE_PREFIX}balanced"

STATUS_IMPLEMENTED = "implemented"
STATUS_PARTIAL = "partial"
STATUS_MISSING = "missing"
STATUS_UNSUPPORTED = "unsupported"
STATUS_NOT_APPLICABLE = "not_applicable"

STATUS_LABELS = {
    STATUS_IMPLEMENTED: "Implemented",
    STATUS_PARTIAL: "Partially Implemented",
    STATUS_MISSING: "Missing",
    STATUS_UNSUPPORTED: "Unsupported",
    STATUS_NOT_APPLICABLE: "Not Applicable",
}

# Feature-by-feature coverage. ``status`` is about this codebase, not the
# engine: "unsupported" means the engine itself cannot do it at the pinned
# version; "missing" means the engine can and the product does not yet.
FEATURES: list[dict[str, str]] = [
    # --- Targets ---
    {
        "area": "Targets",
        "feature": "Container image",
        "status": STATUS_PARTIAL,
        "detail": "Single images and image lists run on the new engine. A source "
        "that is a whole registry still uses the registry scan and gets findings "
        "but no component inventory or lifecycle.",
    },
    {
        "area": "Targets",
        "feature": "Code repository",
        "status": STATUS_IMPLEMENTED,
        "detail": "HTTPS with token (branch, tag, commit) and SSH (branch or "
        "tag cloned, then scanned as a directory). Branches are listed from "
        "the source; one target per branch.",
    },
    {
        "area": "Targets",
        "feature": "Local filesystem",
        "status": STATUS_IMPLEMENTED,
        "detail": "Uploaded ZIP or TAR archive, extracted with path and size checks.",
    },
    {
        "area": "Targets",
        "feature": "Root filesystem",
        "status": STATUS_IMPLEMENTED,
        "detail": "Uploaded archive scanned with installed-package detection.",
    },
    {
        "area": "Targets",
        "feature": "Virtual machine image",
        "status": STATUS_MISSING,
        "detail": UNAVAILABLE_TARGETS["vm"]["reason"],
    },
    {
        "area": "Targets",
        "feature": "Kubernetes cluster",
        "status": STATUS_IMPLEMENTED,
        "detail": "Cluster report parsed per resource; namespace and kind filters; "
        "node collector off by default. Experimental in the engine.",
    },
    {
        "area": "Targets",
        "feature": "SBOM document",
        "status": STATUS_IMPLEMENTED,
        "detail": "CycloneDX JSON and SPDX (JSON, tag-value).",
    },
    {
        "area": "Targets",
        "feature": "Infrastructure as Code repository",
        "status": STATUS_IMPLEMENTED,
        "detail": "Repository scan with the misconfiguration scanner on by default.",
    },
    # --- Vulnerabilities ---
    {
        "area": "Vulnerabilities",
        "feature": "OS and language package vulnerabilities",
        "status": STATUS_IMPLEMENTED,
        "detail": "Class, type, package, installed and "
        "fixed version, status, PURL, layer, data source, vendor ids, CWE, "
        "references, published and modified dates.",
    },
    {
        "area": "Vulnerabilities",
        "feature": "CVSS",
        "status": STATUS_IMPLEMENTED,
        "detail": "All vendor vectors and scores stored. The finding's score is "
        "the base score from the vendor that set the severity (newest CVSS "
        "version), else NVD, else the highest reported.",
    },
    {
        "area": "Vulnerabilities",
        "feature": "Direct and transitive classification",
        "status": STATUS_IMPLEMENTED,
        "detail": "From the package relationship in "
        "the report; unknown when the ecosystem does not provide it.",
    },
    {
        "area": "Vulnerabilities",
        "feature": "EPSS and known-exploited data",
        "status": STATUS_UNSUPPORTED,
        "detail": "The engine reports neither. The "
        "finding has nullable fields and the score counts them only when set; no "
        "feed is connected.",
    },
    {
        "area": "Vulnerabilities",
        "feature": "Separate metrics (instances, unique "
        "CVEs, affected packages, fixable)",
        "status": STATUS_IMPLEMENTED,
        "detail": "Computed by the findings summary endpoint; never one mixed number.",
    },
    {
        "area": "Vulnerabilities",
        "feature": "Kubernetes core component vulnerabilities",
        "status": STATUS_PARTIAL,
        "detail": "Reported when the cluster scan returns them; no separate KBOM view.",
    },
    # --- Misconfiguration ---
    {
        "area": "Misconfigurations",
        "feature": "Built-in checks for all supported formats",
        "status": STATUS_IMPLEMENTED,
        "detail": "Check id (current and legacy "
        "spellings), title, message, resolution, resource, provider, service, "
        "lines, code context, references.",
    },
    {
        "area": "Misconfigurations",
        "feature": "Custom Rego checks",
        "status": STATUS_IMPLEMENTED,
        "detail": "Stored per tenant, versioned, "
        "validated (metadata and package), passed with their namespaces.",
    },
    {
        "area": "Misconfigurations",
        "feature": "Rego check unit testing",
        "status": STATUS_MISSING,
        "detail": "Checks are validated for structure; "
        "running OPA tests against sample input is not built.",
    },
    {
        "area": "Misconfigurations",
        "feature": "Passed checks",
        "status": STATUS_IMPLEMENTED,
        "detail": "Optional per profile; counted in "
        "scan statistics, not stored as findings.",
    },
    {
        "area": "Misconfigurations",
        "feature": "Helm values, Terraform variables, CloudFormation parameters",
        "status": STATUS_MISSING,
        "detail": "The engine accepts override files; the product does not pass them.",
    },
    {
        "area": "Misconfigurations",
        "feature": "Compliance reports (CIS, NSA, PSS)",
        "status": STATUS_MISSING,
        "detail": "The engine's compliance output is a "
        "different report shape and is not ingested.",
    },
    # --- Secrets ---
    {
        "area": "Secrets",
        "feature": "Built-in secret rules",
        "status": STATUS_IMPLEMENTED,
        "detail": "Rule id, category, title, file, lines, masked match and code.",
    },
    {
        "area": "Secrets",
        "feature": "Custom rules, allow rules, disabled rules, skip patterns",
        "status": STATUS_IMPLEMENTED,
        "detail": "One secret configuration document per tenant policy.",
    },
    {
        "area": "Secrets",
        "feature": "Secret value protection",
        "status": STATUS_IMPLEMENTED,
        "detail": "The engine masks matches; the parser masks again before storage, "
        "so neither the database nor the raw artifact holds a full value.",
    },
    {
        "area": "Secrets",
        "feature": "Detection confidence",
        "status": STATUS_UNSUPPORTED,
        "detail": "The engine reports no confidence for secrets.",
    },
    # --- Licenses ---
    {
        "area": "Licenses",
        "feature": "License identification and classification",
        "status": STATUS_IMPLEMENTED,
        "detail": "Seven categories; severity kept "
        "separate from vulnerability severity.",
    },
    {
        "area": "Licenses",
        "feature": "Full license scanning (headers and files)",
        "status": STATUS_IMPLEMENTED,
        "detail": "Image, filesystem, repository and root filesystem targets.",
    },
    {
        "area": "Licenses",
        "feature": "Custom classification and ignored licenses",
        "status": STATUS_IMPLEMENTED,
        "detail": "Tenant license policy written to "
        "the engine configuration for each scan.",
    },
    # --- SBOM ---
    {
        "area": "SBOM",
        "feature": "Component inventory per scan",
        "status": STATUS_IMPLEMENTED,
        "detail": "Name, version, ecosystem, PURL, licenses, relationship, "
        "dependencies, location.",
    },
    {
        "area": "SBOM",
        "feature": "CycloneDX and SPDX export",
        "status": STATUS_IMPLEMENTED,
        "detail": "Converted from the stored report by the engine; a CycloneDX "
        "document built from the stored inventory is the fallback.",
    },
    {
        "area": "SBOM",
        "feature": "SBOM import",
        "status": STATUS_IMPLEMENTED,
        "detail": "SBOM target; the document is scanned and its components stored.",
    },
    {
        "area": "SBOM",
        "feature": "Version comparison",
        "status": STATUS_IMPLEMENTED,
        "detail": "Added, removed and changed components between two inventories.",
    },
    {
        "area": "SBOM",
        "feature": "Continuous monitoring",
        "status": STATUS_PARTIAL,
        "detail": "Scheduled rescans re-evaluate a target against the current "
        "database. Stored inventories are not re-matched without a scan.",
    },
    {
        "area": "SBOM",
        "feature": "SBOM attestation and Rekor lookup",
        "status": STATUS_MISSING,
        "detail": "Experimental in the engine; not wired.",
    },
    # --- Filtering and exceptions ---
    {
        "area": "Exceptions",
        "feature": "Ignore rules (ids, paths, PURLs, expiry)",
        "status": STATUS_IMPLEMENTED,
        "detail": "Tenant ignore policy passed as an "
        "ignore file; suppressed findings are recorded, not dropped.",
    },
    {
        "area": "Exceptions",
        "feature": "VEX (OpenVEX, CSAF, CycloneDX)",
        "status": STATUS_PARTIAL,
        "detail": "Tenant VEX documents are passed to "
        "scans. VEX repositories and OCI VEX are not used. CycloneDX VEX applies "
        "only to CycloneDX SBOM targets (engine rule).",
    },
    {
        "area": "Exceptions",
        "feature": "Rego ignore policy",
        "status": STATUS_MISSING,
        "detail": "The engine accepts one; the product does not pass it.",
    },
    {
        "area": "Exceptions",
        "feature": "Risk acceptance and false positives",
        "status": STATUS_IMPLEMENTED,
        "detail": "Platform triage, with notes and audit log.",
    },
    # --- Engine ---
    {
        "area": "Engine",
        "feature": "Pinned, checksum-verified binary; version on every scan",
        "status": STATUS_IMPLEMENTED,
        "detail": "",
    },
    {
        "area": "Engine",
        "feature": "Timeout, cancellation, separate stdout and stderr, exit code",
        "status": STATUS_IMPLEMENTED,
        "detail": "",
    },
    {
        "area": "Engine",
        "feature": "Retry on database download failure",
        "status": STATUS_IMPLEMENTED,
        "detail": "Bounded, with backoff.",
    },
    {
        "area": "Engine",
        "feature": "Vulnerability database and cache management",
        "status": STATUS_IMPLEMENTED,
        "detail": "Shared snapshot refreshed on a schedule; per-scan cache directory.",
    },
    {
        "area": "Engine",
        "feature": "Resource consumption tracking",
        "status": STATUS_PARTIAL,
        "detail": "Duration and report size are recorded; CPU and memory are not.",
    },
    {
        "area": "Engine",
        "feature": "Network egress controls for the scan process",
        "status": STATUS_MISSING,
        "detail": "Needs deployment-level network policy; "
        "the worker is not sandboxed per scan.",
    },
    {
        "area": "Engine",
        "feature": "Client/server mode",
        "status": STATUS_NOT_APPLICABLE,
        "detail": "Scans run in the worker; the queue already distributes them.",
    },
    {
        "area": "Engine",
        "feature": "Plugins and WebAssembly modules",
        "status": STATUS_NOT_APPLICABLE,
        "detail": "Third-party code in the scan "
        "process is not allowed on a multi-tenant worker.",
    },
    {
        "area": "Engine",
        "feature": "Cryptographic asset discovery (CBOM)",
        "status": STATUS_UNSUPPORTED,
        "detail": "The engine has no such scanner at the pinned version.",
    },
    {
        "area": "Engine",
        "feature": "Semantic static analysis (SAST)",
        "status": STATUS_NOT_APPLICABLE,
        "detail": "Not an engine capability. A "
        "separate engine (OpenGrep) serves the Static analysis target type.",
    },
    # --- Product layer ---
    {
        "area": "Product",
        "feature": "Application and asset inventory",
        "status": STATUS_IMPLEMENTED,
        "detail": "Applications group targets and "
        "carry criticality, environment, exposure and a default profile. Branch "
        "and commit are recorded per scan, not modelled as inventory levels.",
    },
    {
        "area": "Product",
        "feature": "Scan profiles",
        "status": STATUS_IMPLEMENTED,
        "detail": "Six built-in profiles; custom profiles with create, clone, "
        "edit, disable and delete; assignment per target, application and "
        "target type.",
    },
    {
        "area": "Product",
        "feature": "Finding deduplication and lifecycle",
        "status": STATUS_IMPLEMENTED,
        "detail": "One row per fingerprint and "
        "target; new, open, fixed and reopened states with history. A finding is "
        "fixed only when a complete scan that covers it stops reporting it.",
    },
    {
        "area": "Product",
        "feature": "Finding correlation across assets",
        "status": STATUS_PARTIAL,
        "detail": "A finding lists the same advisory or "
        "rule on other assets and other issues in the same package. There is no "
        "merged cross-asset record.",
    },
    {
        "area": "Product",
        "feature": "Risk prioritization",
        "status": STATUS_IMPLEMENTED,
        "detail": "Explainable score from severity, CVSS, fix availability, "
        "dependency directness, application context and age; thresholds are "
        "tenant settings.",
    },
    {
        "area": "Product",
        "feature": "Remediation deadlines",
        "status": STATUS_PARTIAL,
        "detail": "A deadline per severity from first detection, overdue filter "
        "and counts. Ownership is the application owner and the triage "
        "assignee; there are no overdue notifications.",
    },
    {
        "area": "Product",
        "feature": "Dependency tree view",
        "status": STATUS_MISSING,
        "detail": "Dependency edges are stored and exported; the UI lists direct "
        "and transitive packages but draws no tree.",
    },
    {
        "area": "Product",
        "feature": "Outdated package detection",
        "status": STATUS_UNSUPPORTED,
        "detail": "The engine reports fixed versions "
        "for vulnerable packages only; it has no latest-version data.",
    },
    {
        "area": "Product",
        "feature": "Git metadata",
        "status": STATUS_PARTIAL,
        "detail": "Repository URL, branch, commit, author and tags are stored on "
        "the scan for HTTPS repositories. SSH repositories are scanned as a "
        "directory and record only the branch.",
    },
    {
        "area": "Product",
        "feature": "Assistant integration (finding explanation)",
        "status": STATUS_MISSING,
        "detail": "The assistant has no tools for the "
        "new findings, components or applications yet.",
    },
    {
        "area": "Product",
        "feature": "Verification against a live engine",
        "status": STATUS_MISSING,
        "detail": "Parser and command tests use "
        "fixtures built from the engine's types at the pinned version. No scan "
        "has been run against the real binary in this change.",
    },
    # --- Outputs ---
    {
        "area": "Outputs",
        "feature": "JSON, SARIF, CycloneDX, SPDX",
        "status": STATUS_IMPLEMENTED,
        "detail": "Per scan, from the stored report. "
        "Cluster scans export JSON only (engine limit).",
    },
    {
        "area": "Outputs",
        "feature": "CSV and JSON finding exports",
        "status": STATUS_IMPLEMENTED,
        "detail": "From the findings list, with the active filters.",
    },
    {
        "area": "Outputs",
        "feature": "PDF and Excel reports",
        "status": STATUS_PARTIAL,
        "detail": "The existing report catalog (dependencies, containers, "
        "Infrastructure as Code, secrets, static analysis, executive) is "
        "unchanged. License, SBOM and remediation-tracking reports are not added.",
    },
]


def scanners_for(target_type: str) -> tuple[str, ...]:
    """Scanners the engine accepts for a target type (empty if unknown)."""
    spec = TARGETS.get(target_type)
    return tuple(spec["scanners"]) if spec else ()


def options_for(target_type: str) -> tuple[str, ...]:
    """Option names valid for a target type (empty if unknown)."""
    spec = TARGETS.get(target_type)
    return tuple(spec["options"]) if spec else ()


def capability_document() -> dict[str, Any]:
    """Return the matrix the API serves to the UI."""
    targets = []
    for key, spec in TARGETS.items():
        targets.append(
            {
                "id": key,
                "label": spec["label"],
                "experimental": spec["experimental"],
                "scanners": list(spec["scanners"]),
                "default_scanners": list(spec["default_scanners"]),
                "options": list(spec["options"]),
                "export_formats": list(spec["export_formats"]),
                "notes": list(spec["notes"]),
            }
        )
    options = {}
    for name, spec in OPTION_SPECS.items():
        entry = {key: value for key, value in spec.items() if key != "flag"}
        if "choices" in entry:
            entry["choices"] = list(entry["choices"])
        options[name] = entry
    return {
        "engine_version": ENGINE_VERSION,
        "scanners": [
            {"id": key, "label": label} for key, label in SCANNER_LABELS.items()
        ],
        "targets": targets,
        "unavailable_targets": [
            {"id": key, **value} for key, value in UNAVAILABLE_TARGETS.items()
        ],
        "other_engine_targets": [
            {"id": key, "label": value["label"]}
            for key, value in OTHER_ENGINE_TARGETS.items()
        ],
        "options": options,
        "license_categories": list(LICENSE_CATEGORIES),
        "builtin_profiles": [
            {"ref": f"{BUILTIN_PROFILE_PREFIX}{key}", **value}
            for key, value in BUILTIN_PROFILES.items()
        ],
        "default_profile_ref": DEFAULT_PROFILE_REF,
        "features": [
            {**feature, "status_label": STATUS_LABELS[feature["status"]]}
            for feature in FEATURES
        ],
    }
