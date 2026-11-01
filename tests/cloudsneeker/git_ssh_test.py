"""SSH deploy keys for Git clones and the IaC provider hooks."""

import os
import stat
from unittest import mock

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from cloudsneeker import git_ssh
from cloudsneeker.git_ssh import (
    GitSshError,
    clone_error_message,
    is_ssh_url,
    load_private_key,
    ssh_host,
    ssh_secret_args,
    ssh_transport,
    validate_known_hosts,
)
from prowler.providers.iac.exceptions.exceptions import IacRepositoryCloneError
from prowler.providers.iac.iac_provider import IacProvider

SSH_URL = "git@bitbucket.org:acme/app.git"
HOST_LINE = (
    "git.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn"
)


def _openssh_key() -> str:
    return (
        ed25519.Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        .decode()
    )


def _pkcs8_rsa_key(passphrase: bytes | None = None) -> str:
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )
        .decode()
    )


class TestUrls:
    @pytest.mark.parametrize(
        "url",
        [
            SSH_URL,
            "ssh://git@bitbucket.org/acme/app.git",
            "ssh://git@git.example.com:7999/ops/app.git",
            "git@ssh.dev.azure.com:v3/org/project/repo",
        ],
    )
    def test_ssh_urls(self, url):
        assert is_ssh_url(url)

    @pytest.mark.parametrize(
        "url",
        [
            "https://bitbucket.org/acme/app.git",
            "https://jane@bitbucket.org/acme/app.git",
            "http://git.example.com/a.git",
            "",
            None,
            "/local/path",
        ],
    )
    def test_not_ssh_urls(self, url):
        assert not is_ssh_url(url)

    @pytest.mark.parametrize(
        ("url", "host"),
        [
            (SSH_URL, "bitbucket.org"),
            ("ssh://git@Git.Example.com:7999/ops/app.git", "git.example.com"),
        ],
    )
    def test_ssh_host(self, url, host):
        assert ssh_host(url) == host


class TestLoadPrivateKey:
    def test_openssh_key(self):
        loaded = load_private_key(_openssh_key())
        assert loaded.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_pkcs8_pem_key_is_converted(self):
        loaded = load_private_key(_pkcs8_rsa_key())
        assert loaded.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_windows_line_endings(self):
        key = _openssh_key().replace("\n", "\r\n")
        assert load_private_key(key).startswith(b"-----BEGIN OPENSSH")

    def test_encrypted_pem_key_with_passphrase(self):
        loaded = load_private_key(_pkcs8_rsa_key(b"s3cret"), "s3cret")
        # The written key must load without a passphrase.
        serialization.load_ssh_private_key(loaded, password=None)

    def test_encrypted_key_without_passphrase(self):
        with pytest.raises(GitSshError, match="enter its passphrase"):
            load_private_key(_pkcs8_rsa_key(b"s3cret"))

    def test_wrong_passphrase(self):
        with pytest.raises(GitSshError, match="passphrase"):
            load_private_key(_pkcs8_rsa_key(b"s3cret"), "wrong")

    def test_encrypted_openssh_key_needs_conversion(self):
        # Decrypting OpenSSH-format keys needs bcrypt, which is not installed.
        with mock.patch.object(
            serialization,
            "load_ssh_private_key",
            side_effect=UnsupportedAlgorithm("Need bcrypt module"),
        ):
            with pytest.raises(GitSshError, match="ssh-keygen -p -m PEM"):
                load_private_key(_openssh_key(), "s3cret")

    def test_passphrase_for_plain_key(self):
        with pytest.raises(GitSshError, match="not encrypted"):
            load_private_key(_openssh_key(), "unneeded")

    @pytest.mark.parametrize(
        "text", ["", "   ", "not a key", "ssh-ed25519 AAAA public"]
    )
    def test_rejects_non_keys(self, text):
        with pytest.raises(GitSshError):
            load_private_key(text)

    def test_error_never_contains_the_key(self):
        key = _openssh_key()
        broken = key.replace(
            "OPENSSH PRIVATE KEY-----\n", "OPENSSH PRIVATE KEY-----\nAAAA", 1
        )
        with pytest.raises(GitSshError) as error:
            load_private_key(broken)
        assert key.splitlines()[1][:20] not in str(error.value)


class TestKnownHosts:
    def test_normalizes_lines(self):
        text = f"# comment\n\n  {HOST_LINE}  extra-comment\r\n"
        assert validate_known_hosts(text) == HOST_LINE

    def test_empty(self):
        assert validate_known_hosts(None) == ""
        assert validate_known_hosts("\n# only comments\n") == ""

    @pytest.mark.parametrize(
        "line",
        [
            "git.example.com",
            "git.example.com ssh-dss AAAA",
            "git.example.com ssh-ed25519 not-base64!",
            "@cert-authority *.example.com ssh-ed25519 AAAA",
        ],
    )
    def test_rejects_malformed(self, line):
        with pytest.raises(GitSshError):
            validate_known_hosts(line)

    def test_pinned_hosts_cover_public_forges(self):
        hosts = {line.split()[0] for line in git_ssh.PINNED_KNOWN_HOSTS.splitlines()}
        assert {
            "github.com",
            "gitlab.com",
            "bitbucket.org",
            "ssh.dev.azure.com",
        } <= hosts


class TestSshTransport:
    def test_https_needs_nothing(self):
        with ssh_transport("https://bitbucket.org/acme/app.git") as kwargs:
            assert kwargs == {}

    def test_ssh_url_requires_a_key(self):
        with pytest.raises(GitSshError, match="SSH private key"):
            with ssh_transport(SSH_URL):
                pass

    def test_writes_private_files_and_cleans_up(self):
        with ssh_transport(SSH_URL, _openssh_key(), HOST_LINE) as kwargs:
            key_path = kwargs["key_filename"]
            directory = os.path.dirname(key_path)
            assert os.path.isfile(key_path)
            if os.name == "posix":
                assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
                assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700
            command = kwargs["ssh_command"]
            assert "StrictHostKeyChecking=yes" in command
            assert "BatchMode=yes" in command
            assert "IdentitiesOnly=yes" in command
            hosts_file = os.path.join(directory, "known_hosts")
            with open(hosts_file, encoding="ascii") as handle:
                content = handle.read()
            assert "bitbucket.org ssh-ed25519" in content
            assert HOST_LINE in content
        assert not os.path.exists(directory)

    def test_cleans_up_when_the_clone_fails(self):
        with pytest.raises(RuntimeError):
            with ssh_transport(SSH_URL, _openssh_key()) as kwargs:
                directory = os.path.dirname(kwargs["key_filename"])
                raise RuntimeError("clone failed")
        assert not os.path.exists(directory)


class TestCloneAndLsRemote:
    @mock.patch("dulwich.porcelain.clone")
    def test_https_clone_is_unchanged(self, mock_clone):
        git_ssh.clone("https://x:tok@bitbucket.org/a/b.git", "/tmp/d", depth=1)
        mock_clone.assert_called_once_with(
            "https://x:tok@bitbucket.org/a/b.git", "/tmp/d", depth=1
        )

    @mock.patch("dulwich.porcelain.clone")
    def test_ssh_clone_passes_key_and_command(self, mock_clone):
        git_ssh.clone(SSH_URL, "/tmp/d", _openssh_key(), None, None, depth=1)
        kwargs = mock_clone.call_args.kwargs
        assert kwargs["depth"] == 1
        assert kwargs["key_filename"].endswith("id_key")
        assert kwargs["ssh_command"].startswith("ssh ")

    @mock.patch(
        "dulwich.porcelain.clone",
        side_effect=Exception("Host key verification failed."),
    )
    def test_ssh_clone_error_is_actionable(self, _mock_clone):
        with pytest.raises(GitSshError, match="host key"):
            git_ssh.clone(SSH_URL, "/tmp/d", _openssh_key())

    @mock.patch("dulwich.porcelain.ls_remote")
    def test_ls_remote_over_ssh(self, mock_ls_remote):
        git_ssh.ls_remote(SSH_URL, _openssh_key())
        assert "key_filename" in mock_ls_remote.call_args.kwargs

    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            ("Permission denied (publickey).", "deploy key"),
            ("ssh: Could not resolve hostname x", "could not be reached"),
            ("something else", "SSH clone failed"),
        ],
    )
    def test_error_messages(self, message, expected):
        assert expected in clone_error_message(message)

    def test_ssh_secret_args(self):
        assert ssh_secret_args(None) == (None, None, None)
        assert ssh_secret_args(
            {"ssh_private_key": "k", "ssh_known_hosts": "", "ssh_key_passphrase": "p"}
        ) == ("k", None, "p")


class TestIacProviderSshHooks:
    @mock.patch("prowler.providers.iac.iac_provider.porcelain.clone")
    def test_clone_uses_the_ssh_key(self, mock_clone):
        provider = IacProvider()
        provider.git_ssh = (_openssh_key(), None, None)
        with mock.patch.object(provider, "_detect_branch_name", return_value="main"):
            provider._clone_repository(SSH_URL)
        assert mock_clone.call_args.args[0] == SSH_URL
        assert "key_filename" in mock_clone.call_args.kwargs

    def test_ssh_url_without_key_fails_cleanly(self):
        with pytest.raises(IacRepositoryCloneError):
            IacProvider(scan_repository_url=SSH_URL)

    @mock.patch("prowler.providers.iac.iac_provider.porcelain.clone")
    def test_init_accepts_ssh_fields(self, mock_clone):
        with mock.patch.object(IacProvider, "_detect_branch_name", return_value="main"):
            provider = IacProvider(
                scan_repository_url=SSH_URL, ssh_private_key=_openssh_key()
            )
        assert provider.git_ssh[0]
        assert "ssh_command" in mock_clone.call_args.kwargs

    @mock.patch("prowler.providers.iac.iac_provider.porcelain.ls_remote")
    def test_test_connection_over_ssh(self, mock_ls_remote):
        connection = IacProvider.test_connection(
            scan_repository_url=SSH_URL,
            ssh_private_key=_openssh_key(),
            raise_on_exception=False,
        )
        assert connection.is_connected
        assert "key_filename" in mock_ls_remote.call_args.kwargs

    @mock.patch(
        "prowler.providers.iac.iac_provider.porcelain.ls_remote",
        side_effect=Exception("Permission denied (publickey)."),
    )
    def test_test_connection_reports_refused_key(self, _mock_ls_remote):
        connection = IacProvider.test_connection(
            scan_repository_url=SSH_URL,
            ssh_private_key=_openssh_key(),
            raise_on_exception=False,
        )
        assert not connection.is_connected
        assert "deploy key" in str(connection.error)
