"""SSH transport for cloning private Git repositories.

The IaC provider, Application Security repository scans and static code
analysis clone over HTTPS with a token (:mod:`cloudsneeker.git_auth`). A
repository URL in SSH form (``git@host:owner/repo.git`` or
``ssh://git@host[:port]/owner/repo.git``) clones with a private key instead.

How a clone runs:

* The key is loaded with ``cryptography`` (OpenSSH, PKCS#1 or PKCS#8 PEM,
  optionally passphrase-protected) and written unencrypted to a ``0600`` file
  in a private temporary directory that is removed when the clone ends.
* ``ssh`` runs with ``BatchMode``, ``IdentitiesOnly`` and
  ``StrictHostKeyChecking=yes`` against a known-hosts file holding the pinned
  keys of github.com, gitlab.com, bitbucket.org and Azure DevOps plus any
  lines the user stored with the key. An unknown host key fails the clone;
  nothing is trusted on first use.
* Dulwich's subprocess SSH vendor needs the ``ssh`` client
  (``openssh-client`` in the API image).

Nothing here logs. Error text never contains the key.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit

SSH_PRIVATE_KEY = "ssh_private_key"
SSH_KNOWN_HOSTS = "ssh_known_hosts"
SSH_KEY_PASSPHRASE = "ssh_key_passphrase"

CONNECT_TIMEOUT_SECONDS = 20

# Fingerprints checked on 2026-11-01 against each host's published values
# (GitHub: api.github.com/meta; GitLab, Bitbucket and Azure DevOps: their
# SSH documentation). Update when a host rotates its keys.
PINNED_KNOWN_HOSTS = """\
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf
gitlab.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=
gitlab.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+jqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY92WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHMoX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1QL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9
bitbucket.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIazEu89wgQZ4bqs3d63QSMzYVa0MuJ2e2gKTKqu+UUO
bitbucket.org ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPIQmuzMBuKdWeF4+a2sjSSpBK0iqitSQ+5BM9KhpexuGt20JpTVM7u5BDZngncgrqDMbWdxMWWOGtZ9UgbqgZE=
bitbucket.org ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQeJzhupRu0u0cdegZIa8e86EG2qOCsIsD1Xw0xSeiPDlCr7kq97NLmMbpKTX6Esc30NuoqEEHCuc7yWtwp8dI76EEEB1VqY9QJq6vk+aySyboD5QF61I/1WeTwu+deCbgKMGbUijeXhtfbxSxm6JwGrXrhBdofTsbKRUsrN1WoNgUa8uqN1Vx6WAJw1JHPhglEGGHea6QICwJOAr/6mrui/oB7pkaWKHj3z7d1IC4KWLtY47elvjbaTlkN04Kc/5LFEirorGYVbt15kAUlqGM65pk6ZBxtaO3+30LVlORZkxOh+LKL/BvbZ/iRNhItLqNyieoQj/uh/7Iv4uyH/cV/0b4WDSd3DptigWq84lJubb9t/DnZlrJazxyDCulTmKdOR7vs9gMTo+uoIrPSb8ScTtvw65+odKAlBj59dhnVp9zd7QUojOpXlL62Aw56U4oO+FALuevvMjiWeavKhJqlR7i5n9srYcrNV7ttmDw7kf/97P5zauIhxcjX+xHv4M=
ssh.dev.azure.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7Hr1oTWqNqOlzGJOfGJ4NakVyIzf1rXYd4d7wo6jBlkLvCA4odBlL0mDUyZ0/QUfTTqeu+tm22gOsv+VrVTMk6vwRU75gY/y9ut5Mb3bR5BV58dKXyq9A9UeB5Cakehn5Zgm6x1mKoVyf+FFn26iYqXJRgzIZZcZ5V6hrE0Qg39kZm4az48o0AUbf6Sp4SLdvnuMa2sVNwHBboS7EJkm57XQPVU3/QpyNLHbWDdzwtrlS+ez30S3AdYhLKEOxAG8weOnyrtLJAUen9mTkol8oII1edf7mWWbWVf0nBmly21+nZcmCTISQBtdcyPaEno7fFQMDD26/s0lfKob4Kw8H
vs-ssh.visualstudio.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7Hr1oTWqNqOlzGJOfGJ4NakVyIzf1rXYd4d7wo6jBlkLvCA4odBlL0mDUyZ0/QUfTTqeu+tm22gOsv+VrVTMk6vwRU75gY/y9ut5Mb3bR5BV58dKXyq9A9UeB5Cakehn5Zgm6x1mKoVyf+FFn26iYqXJRgzIZZcZ5V6hrE0Qg39kZm4az48o0AUbf6Sp4SLdvnuMa2sVNwHBboS7EJkm57XQPVU3/QpyNLHbWDdzwtrlS+ez30S3AdYhLKEOxAG8weOnyrtLJAUen9mTkol8oII1edf7mWWbWVf0nBmly21+nZcmCTISQBtdcyPaEno7fFQMDD26/s0lfKob4Kw8H
"""

# ``user@host:path`` (scp-like); the path must not start with ``//``.
_SCP_LIKE = re.compile(
    r"^(?P<user>[A-Za-z0-9._-]+)@(?P<host>[A-Za-z0-9.-]+):(?!//)(?P<path>.+)$"
)
_KEY_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)
_BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


class GitSshError(ValueError):
    """An SSH key, host key or SSH clone problem the user can fix."""


def is_ssh_url(repository_url: str | None) -> bool:
    """Whether ``repository_url`` clones over SSH.

    Args:
        repository_url: Repository URL.

    Returns:
        ``True`` for ``ssh://`` URLs and scp-like ``user@host:path``.
    """
    value = (repository_url or "").strip()
    if value.lower().startswith("ssh://"):
        return True
    return bool(_SCP_LIKE.match(value))


def ssh_host(repository_url: str) -> str:
    """Return the host name of an SSH repository URL, lowercased.

    Args:
        repository_url: ``ssh://`` or scp-like URL.

    Returns:
        The host, or ``""`` when it cannot be read.
    """
    value = (repository_url or "").strip()
    match = _SCP_LIKE.match(value)
    if match:
        return match.group("host").lower()
    try:
        return (urlsplit(value).hostname or "").lower()
    except ValueError:
        return ""


def load_private_key(private_key: str, passphrase: str | None = None) -> bytes:
    """Return ``private_key`` as an unencrypted OpenSSH private key.

    Args:
        private_key: OpenSSH, PKCS#1 or PKCS#8 PEM text.
        passphrase: Passphrase when the key is encrypted.

    Returns:
        The key in OpenSSH format, ready for ``ssh -i``.

    Raises:
        GitSshError: The text is not a supported private key, or the
            passphrase is missing or wrong.
    """
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization

    data = (private_key or "").strip().replace("\r\n", "\n").encode()
    if not data:
        raise GitSshError("An SSH private key is required.")
    password = passphrase.encode() if passphrase else None
    loaders = (serialization.load_ssh_private_key, serialization.load_pem_private_key)
    for loader in loaders:
        try:
            key = loader(data + b"\n", password=password)
        except UnsupportedAlgorithm as error:
            # Decrypting OpenSSH-format keys needs the optional bcrypt module.
            if loader is serialization.load_ssh_private_key and password:
                raise GitSshError(
                    "Passphrase-protected keys in OpenSSH format are not supported. "
                    "Use a deploy key without a passphrase, or convert the key to "
                    "PEM with 'ssh-keygen -p -m PEM -f <key>'."
                ) from error
            continue
        except TypeError as error:
            # Encrypted key without a passphrase, or a passphrase for a plain key.
            raise GitSshError(
                "The SSH key is encrypted: enter its passphrase."
                if not password
                else "The SSH key is not encrypted: leave the passphrase empty."
            ) from error
        except Exception:  # noqa: BLE001 - wrong format, bad passphrase, unsupported type
            continue
        try:
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption(),
            )
        except Exception as error:  # noqa: BLE001
            raise GitSshError("This SSH key type is not supported.") from error
    if password:
        raise GitSshError(
            "The SSH private key could not be read: check the key and its passphrase."
        ) from None
    raise GitSshError(
        "The SSH private key could not be read. Paste the whole key, including "
        "its BEGIN and END lines."
    ) from None


def validate_known_hosts(known_hosts: str | None) -> str:
    """Check user-supplied known-hosts lines and return them normalized.

    Each line is ``host[,host...] key-type base64-key`` (the format
    ``ssh-keyscan`` prints). Blank lines and ``#`` comments are dropped.

    Args:
        known_hosts: Text, possibly empty.

    Returns:
        The lines joined with ``\\n`` (``""`` when there are none).

    Raises:
        GitSshError: A line is not a host key line.
    """
    lines = []
    for raw in (known_hosts or "").replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if (
            len(parts) < 3
            or parts[0].startswith("@")
            or parts[1] not in _KEY_TYPES
            or not _BASE64.match(parts[2])
        ):
            raise GitSshError(
                "Each SSH host key line must look like "
                "'git.example.com ssh-ed25519 AAAA...', as ssh-keyscan prints it."
            )
        lines.append(" ".join(parts[:3]))
    return "\n".join(lines)


def clone_error_message(error: BaseException | str) -> str:
    """Turn an SSH clone failure into an actionable message.

    Args:
        error: Exception or text from Dulwich / ``ssh``.

    Returns:
        A message without key material.
    """
    text = str(error)
    lowered = text.lower()
    if "host key verification failed" in lowered or "no matching host key" in lowered:
        return (
            "The Git server's SSH host key is unknown. Add its host key "
            "(the output of 'ssh-keyscan <host>') to the provider credentials."
        )
    if "permission denied" in lowered:
        return (
            "The Git server refused the SSH key. Add its public key to the "
            "repository or account as a read-only deploy key."
        )
    if "no such file or directory" in lowered and "ssh" in lowered:
        return "The SSH client is not installed on this server."
    if "could not resolve" in lowered or "timed out" in lowered:
        return "The Git server could not be reached over SSH."
    return f"SSH clone failed: {text}"


@contextmanager
def ssh_transport(
    repository_url: str,
    private_key: str | None = None,
    known_hosts: str | None = None,
    passphrase: str | None = None,
) -> Iterator[dict[str, str]]:
    """Yield Dulwich keyword arguments that clone ``repository_url`` over SSH.

    Use as ``with ssh_transport(url, key) as kwargs: porcelain.clone(url,
    dest, **kwargs)``. HTTPS URLs yield ``{}``, so callers need no branch.

    Args:
        repository_url: Repository URL.
        private_key: Private key text. Required for SSH URLs.
        known_hosts: Extra known-hosts lines for self-hosted servers.
        passphrase: Passphrase of an encrypted key.

    Yields:
        ``{"ssh_command": ..., "key_filename": ...}`` for SSH URLs, else ``{}``.

    Raises:
        GitSshError: Missing or unreadable key, or invalid host key lines.
    """
    if not is_ssh_url(repository_url):
        yield {}
        return
    if not private_key:
        raise GitSshError("This repository URL uses SSH: add an SSH private key.")

    key_bytes = load_private_key(private_key, passphrase)
    extra_hosts = validate_known_hosts(known_hosts)
    directory = tempfile.mkdtemp(prefix="git-ssh-")
    try:
        os.chmod(directory, 0o700)
        key_path = os.path.join(directory, "id_key")
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(key_bytes)
        hosts_path = os.path.join(directory, "known_hosts")
        with open(hosts_path, "w", encoding="ascii") as handle:
            handle.write(PINNED_KNOWN_HOSTS)
            if extra_hosts:
                handle.write(extra_hosts + "\n")
        options = [
            "-F",
            os.devnull,
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={hosts_path}",
            "-o",
            f"GlobalKnownHostsFile={os.devnull}",
            "-o",
            f"ConnectTimeout={CONNECT_TIMEOUT_SECONDS}",
        ]
        yield {
            "ssh_command": shlex.join(["ssh", *options]),
            "key_filename": key_path,
        }
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def clone(
    repository_url: str,
    target: str,
    private_key: str | None = None,
    known_hosts: str | None = None,
    passphrase: str | None = None,
    **kwargs,
):
    """``dulwich.porcelain.clone`` that also clones SSH URLs with a key.

    Args:
        repository_url: HTTPS (possibly authenticated) or SSH URL.
        target: Directory to clone into.
        private_key: Private key for SSH URLs.
        known_hosts: Extra known-hosts lines.
        passphrase: Passphrase of an encrypted key.
        **kwargs: Passed to ``porcelain.clone`` (``depth``, ``errstream``...).

    Returns:
        The cloned ``dulwich.repo.Repo``.

    Raises:
        GitSshError: SSH setup or an SSH clone failed.
    """
    from dulwich import porcelain

    with ssh_transport(
        repository_url, private_key, known_hosts, passphrase
    ) as transport:
        if not transport:
            return porcelain.clone(repository_url, target, **kwargs)
        try:
            return porcelain.clone(repository_url, target, **kwargs, **transport)
        except Exception as error:  # noqa: BLE001 - dulwich/ssh raise many types
            raise GitSshError(clone_error_message(error)) from None


def ls_remote(
    repository_url: str,
    private_key: str | None = None,
    known_hosts: str | None = None,
    passphrase: str | None = None,
):
    """``dulwich.porcelain.ls_remote`` that also reaches SSH URLs with a key.

    Args:
        repository_url: HTTPS (possibly authenticated) or SSH URL.
        private_key: Private key for SSH URLs.
        known_hosts: Extra known-hosts lines.
        passphrase: Passphrase of an encrypted key.

    Returns:
        Dulwich's ``ls_remote`` result.

    Raises:
        GitSshError: SSH setup or the SSH connection failed.
    """
    from dulwich import porcelain

    with ssh_transport(
        repository_url, private_key, known_hosts, passphrase
    ) as transport:
        if not transport:
            return porcelain.ls_remote(repository_url)
        try:
            return porcelain.ls_remote(repository_url, **transport)
        except Exception as error:  # noqa: BLE001
            raise GitSshError(clone_error_message(error)) from None


def ssh_secret_args(secret: dict | None) -> tuple[str | None, str | None, str | None]:
    """Read ``(private_key, known_hosts, passphrase)`` from a provider secret.

    Args:
        secret: Provider secret dict, possibly ``None``.

    Returns:
        The three values; missing ones are ``None``.
    """
    secret = secret or {}
    return (
        secret.get(SSH_PRIVATE_KEY) or None,
        secret.get(SSH_KNOWN_HOSTS) or None,
        secret.get(SSH_KEY_PASSPHRASE) or None,
    )
