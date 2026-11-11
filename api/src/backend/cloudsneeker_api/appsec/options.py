"""Scan option validation and engine argument construction.

Options are validated against ``capabilities`` for the target type, so a
profile or target can never produce a flag the command does not accept.
Arguments are built as a list (never a shell string) and every user value is
checked so it cannot be read as a flag.
"""

from __future__ import annotations

import re
from typing import Any

from cloudsneeker_api.appsec import capabilities as caps

MAX_LIST_ITEMS = 100
MAX_ITEM_LENGTH = 300

_GLOB_RE = re.compile(r"^[\w@%+=:./*?\[\]!~ -]+$")
_REF_RE = re.compile(r"^[\w][\w./@+-]{0,199}$")
_K8S_NAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,251}[a-zA-Z0-9])?$")
_PLATFORM_RE = re.compile(r"^[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?$")
_LICENSE_RE = re.compile(r"^[\w.+() -]{1,100}$")


class OptionError(ValueError):
    """A scan option is unknown, malformed, or not valid for the target."""


def _string_list(name: str, value: Any, pattern: re.Pattern | None = None) -> list[str]:
    if not isinstance(value, list):
        raise OptionError(f"{name} must be a list.")
    if len(value) > MAX_LIST_ITEMS:
        raise OptionError(f"{name} accepts at most {MAX_LIST_ITEMS} entries.")
    cleaned: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise OptionError(f"{name} entries must be non-empty text.")
        item = item.strip()
        if len(item) > MAX_ITEM_LENGTH:
            raise OptionError(
                f"{name} entries are limited to {MAX_ITEM_LENGTH} characters."
            )
        # The engine takes comma-separated lists; a comma would split an entry.
        if item.startswith("-") or "," in item:
            raise OptionError(f"{name} entry is not valid: {item}")
        if pattern is not None and not pattern.match(item):
            raise OptionError(f"{name} entry is not valid: {item}")
        if item not in cleaned:
            cleaned.append(item)
    return cleaned


def _clean_value(name: str, spec: dict[str, Any], value: Any) -> Any:
    kind = spec["type"]
    if kind == "bool":
        if not isinstance(value, bool):
            raise OptionError(f"{name} must be true or false.")
        return value
    if kind == "choices":
        items = _string_list(name, value)
        allowed = spec["choices"]
        normalized = [
            item.upper() if name == "severities" else item.lower() for item in items
        ]
        unknown = [item for item in normalized if item not in allowed]
        if unknown:
            raise OptionError(
                f"{name} does not accept: {', '.join(unknown)}. "
                f"Choose from: {', '.join(allowed)}."
            )
        return [item for item in allowed if item in normalized]
    if kind == "choice":
        if not isinstance(value, str) or value.lower() not in spec["choices"]:
            raise OptionError(f"{name} must be one of: {', '.join(spec['choices'])}.")
        return value.lower()
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise OptionError(f"{name} must be a whole number.")
        if not spec["min"] <= value <= spec["max"]:
            raise OptionError(
                f"{name} must be between {spec['min']} and {spec['max']}."
            )
        return value
    if kind == "float":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise OptionError(f"{name} must be a number.")
        if not spec["min"] <= value <= spec["max"]:
            raise OptionError(
                f"{name} must be between {spec['min']:g} and {spec['max']:g}."
            )
        return float(value)
    if kind == "globs":
        items = _string_list(name, value, _GLOB_RE)
        if any(".." in item.split("/") for item in items):
            raise OptionError(f"{name} entries must not contain '..'.")
        return items
    if kind == "strings":
        return _string_list(name, value, _LICENSE_RE)
    if kind == "k8s_names":
        return _string_list(name, value, _K8S_NAME_RE)
    if kind == "ref":
        if not isinstance(value, str) or not _REF_RE.match(value.strip()):
            raise OptionError(f"{name} is not a valid Git reference.")
        return value.strip()
    if kind == "platform":
        if not isinstance(value, str) or not _PLATFORM_RE.match(value.strip()):
            raise OptionError(f"{name} must look like linux/amd64.")
        return value.strip()
    raise OptionError(f"{name} has no validator.")


def normalize_scanners(
    target_type: str, scanners: Any, *, strict: bool = True
) -> list[str]:
    """Return the scanners to run for a target type.

    Args:
        target_type: Key of ``capabilities.TARGETS``.
        scanners: Requested scanner names, or ``None`` for the default.
        strict: Reject unsupported scanners. When False they are dropped,
            which is how one profile serves several target types.

    Raises:
        OptionError: Malformed list, or (strict) an unsupported scanner, or
            nothing left to run.
    """
    spec = caps.TARGETS.get(target_type)
    if spec is None:
        raise OptionError(f"Unknown target type: {target_type}.")
    if scanners is None:
        return list(spec["default_scanners"])
    requested = [item.lower() for item in _string_list("scanners", scanners)]
    unsupported = [item for item in requested if item not in spec["scanners"]]
    if unsupported and strict:
        raise OptionError(
            f"{spec['label']} does not support: {', '.join(unsupported)}. "
            f"Choose from: {', '.join(spec['scanners'])}."
        )
    selected = [item for item in spec["scanners"] if item in requested]
    if not selected:
        if not requested:
            raise OptionError("Select at least one scanner.")
        raise OptionError(
            f"None of the selected scanners ({', '.join(requested)}) is "
            f"available for {spec['label']}."
        )
    return selected


def validate_options(
    target_type: str, options: dict[str, Any] | None, *, strict: bool = True
) -> dict[str, Any]:
    """Validate scan options for one target type.

    Args:
        target_type: Key of ``capabilities.TARGETS``.
        options: Raw options (``scanners`` plus ``OPTION_SPECS`` names).
        strict: Reject options and scanners the target does not support.
            When False they are dropped (a shared profile applied to a
            target type that lacks them).

    Returns:
        Cleaned options holding only supported, explicitly set values.

    Raises:
        OptionError: See above.
    """
    spec = caps.TARGETS.get(target_type)
    if spec is None:
        raise OptionError(f"Unknown target type: {target_type}.")
    if options is None:
        options = {}
    if not isinstance(options, dict):
        raise OptionError("Scan options must be an object.")

    cleaned: dict[str, Any] = {
        "scanners": normalize_scanners(
            target_type, options.get("scanners"), strict=strict
        )
    }
    allowed = set(spec["options"])
    for name, value in options.items():
        if name == "scanners" or value is None:
            continue
        option_spec = caps.OPTION_SPECS.get(name)
        if option_spec is None:
            raise OptionError(f"Unknown scan option: {name}.")
        if name not in allowed:
            if strict:
                raise OptionError(f"{spec['label']} does not support {name}.")
            continue
        scanner = option_spec.get("scanner")
        value = _clean_value(name, option_spec, value)
        if scanner and scanner not in cleaned["scanners"]:
            # Valid, but the scanner it tunes is off; keep the run honest.
            continue
        if value in ([], ""):
            continue
        cleaned[name] = value

    refs = [name for name in ("branch", "tag", "commit") if cleaned.get(name)]
    if len(refs) > 1:
        raise OptionError("Set only one of branch, tag or commit.")
    return cleaned


def validate_profile_options(
    options: dict[str, Any] | None, target_types: list[str] | None
) -> dict[str, Any]:
    """Validate a profile's options against every target type it serves.

    A profile is valid when each target type accepts at least one of its
    scanners and every option is valid for at least one of them.

    Raises:
        OptionError: See above.
    """
    types = list(target_types or caps.TARGETS.keys())
    unknown = [item for item in types if item not in caps.TARGETS]
    if unknown:
        raise OptionError(f"Unknown target type: {', '.join(unknown)}.")
    if not isinstance(options, dict):
        raise OptionError("Scan options must be an object.")
    for name in options:
        if name != "scanners" and name not in caps.OPTION_SPECS:
            raise OptionError(f"Unknown scan option: {name}.")
        if name != "scanners" and not any(
            name in caps.TARGETS[item]["options"] for item in types
        ):
            raise OptionError(f"{name} is not supported by any selected target type.")
    for target_type in types:
        validate_options(target_type, options, strict=False)
    return options


def merge_options(*layers: dict[str, Any] | None) -> dict[str, Any]:
    """Merge option layers; later layers win, ``None`` values are skipped."""
    merged: dict[str, Any] = {}
    for layer in layers:
        for key, value in (layer or {}).items():
            if value is not None:
                merged[key] = value
    return merged


def build_scan_args(
    target_type: str,
    options: dict[str, Any],
    *,
    has_vex: bool = False,
    extra_flags: list[str] | None = None,
) -> list[str]:
    """Build the engine flags (no binary, subcommand or target) for a scan.

    The report is always JSON with every package listed and suppressed
    findings shown, so the parser sees the full result.

    Args:
        target_type: Key of ``capabilities.TARGETS``.
        options: Output of :func:`validate_options`.
        has_vex: A VEX document will be passed; ``--pkg-relationships`` is
            then dropped because the engine rejects the combination.
        extra_flags: Policy file flags added by the engine.

    Returns:
        Flag list, each flag and its value as separate items.
    """
    options = validate_options(target_type, options, strict=False)
    args = [
        "--format",
        "json",
        "--quiet",
        "--no-progress",
        "--list-all-pkgs",
        "--show-suppressed",
        "--disable-telemetry",
        "--skip-version-check",
        "--scanners",
        ",".join(options["scanners"]),
    ]
    if target_type == "k8s":
        args.extend(["--report", "all"])
        if "disable_node_collector" not in options:
            options["disable_node_collector"] = True
    if target_type == "image":
        args.extend(["--image-src", "remote"])

    for name in caps.TARGETS[target_type]["options"]:
        if name not in options:
            continue
        value = options[name]
        spec = caps.OPTION_SPECS[name]
        flag = spec["flag"]
        if name == "pkg_relationships" and has_vex:
            continue
        if spec["type"] == "bool":
            if value:
                args.append(flag)
        elif name == "timeout_seconds":
            args.extend([flag, f"{value}s"])
        elif isinstance(value, list):
            args.extend([flag, ",".join(value)])
        else:
            args.extend([flag, str(value)])
    args.extend(extra_flags or [])
    return args


def engine_timeout_seconds(options: dict[str, Any], default: int) -> int:
    """Wall-clock limit for the scan process."""
    value = options.get("timeout_seconds")
    return int(value) if isinstance(value, int) and value > 0 else default
