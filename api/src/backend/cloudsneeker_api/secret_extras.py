"""SSH key fields on the IaC provider secret.

An IaC provider whose repository URL is in SSH form (``git@host:owner/repo``
or ``ssh://...``) clones with ``ssh_private_key`` instead of a token, through
:mod:`cloudsneeker.git_ssh`. Upstream code calls the two helpers here from
one hook line each (``api/v1/serializers.py`` and ``api/utils.py``).
"""

from __future__ import annotations

from cloudsneeker.git_ssh import (
    PINNED_KNOWN_HOSTS,
    SSH_KEY_PASSPHRASE,
    SSH_KNOWN_HOSTS,
    SSH_PRIVATE_KEY,
    GitSshError,
    is_ssh_url,
    load_private_key,
    ssh_host,
    validate_known_hosts,
)
from rest_framework import serializers

PINNED_HOSTS = frozenset(
    line.split()[0] for line in PINNED_KNOWN_HOSTS.splitlines() if line
)

SSH_FIELDS = (SSH_PRIVATE_KEY, SSH_KNOWN_HOSTS, SSH_KEY_PASSPHRASE)


def _known_host_names(known_hosts: str) -> set[str]:
    names: set[str] = set()
    for line in known_hosts.splitlines():
        for name in line.split()[0].split(","):
            # ``[host]:port`` entries name a host on a non-default port.
            names.add(name.strip("[").split("]")[0].lower())
    return names


def validate_iac_ssh_secret(attrs: dict) -> dict:
    """Validate SSH fields on an IaC provider secret.

    Args:
        attrs: Validated ``IacProviderSecret`` fields.

    Returns:
        ``attrs`` with known-hosts lines normalized and empty SSH fields
        removed. The IaC secret is stored as submitted, so these values are
        checked again when a clone runs.

    Raises:
        serializers.ValidationError: The key is missing, unreadable, or used
            with an HTTPS URL, or the host key of a self-hosted server is
            missing or malformed.
    """
    for field in SSH_FIELDS:
        if not attrs.get(field):
            attrs.pop(field, None)

    repository_url = str(attrs.get("repository_url") or "")
    private_key = attrs.get(SSH_PRIVATE_KEY)
    if not is_ssh_url(repository_url):
        if private_key:
            raise serializers.ValidationError(
                {
                    SSH_PRIVATE_KEY: "An SSH key needs an SSH repository URL, "
                    "for example git@bitbucket.org:workspace/repository.git."
                }
            )
        return attrs

    if not private_key:
        raise serializers.ValidationError(
            {SSH_PRIVATE_KEY: "This repository URL uses SSH: add an SSH private key."}
        )
    try:
        load_private_key(private_key, attrs.get(SSH_KEY_PASSPHRASE))
    except GitSshError as error:
        raise serializers.ValidationError({SSH_PRIVATE_KEY: str(error)}) from None
    try:
        known_hosts = validate_known_hosts(attrs.get(SSH_KNOWN_HOSTS))
    except GitSshError as error:
        raise serializers.ValidationError({SSH_KNOWN_HOSTS: str(error)}) from None
    if known_hosts:
        attrs[SSH_KNOWN_HOSTS] = known_hosts

    host = ssh_host(repository_url)
    if host not in PINNED_HOSTS and host not in _known_host_names(known_hosts):
        raise serializers.ValidationError(
            {
                SSH_KNOWN_HOSTS: f"Add the SSH host key of {host or 'the Git server'} "
                f"(the output of 'ssh-keyscan {host or '<host>'}')."
            }
        )
    return attrs


def iac_ssh_kwargs(secret: dict | None) -> dict[str, str]:
    """Return the SSH keyword arguments for ``IacProvider`` from a secret.

    Args:
        secret: Stored provider secret.

    Returns:
        Only the SSH fields that are set.
    """
    secret = secret or {}
    return {field: secret[field] for field in SSH_FIELDS if secret.get(field)}
