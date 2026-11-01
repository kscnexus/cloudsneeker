"""SSH deploy keys: IaC secret validation, provider kwargs, repo scans, SAST."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from api.v1.serializers import IacProviderSecret
from cloudsneeker_api.secret_extras import iac_ssh_kwargs, validate_iac_ssh_secret
from cloudsneeker_api.services.sast import clone_repository
from cloudsneeker_api.services.trivy import (
    TrivyHubError,
    _has_embedded_credentials,
    build_trivy_command,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from rest_framework import serializers

SSH_URL = "git@bitbucket.org:acme/app.git"
SELF_HOSTED_URL = "ssh://git@git.example.com:7999/ops/app.git"
HOST_LINE = "[git.example.com]:7999 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjqu"


def _key() -> str:
    return (
        ed25519.Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        .decode()
    )


def _iac_provider(secret: dict) -> MagicMock:
    provider = MagicMock()
    provider.provider = "iac"
    provider.uid = secret.get("repository_url", SSH_URL)
    provider.secret.secret = secret
    return provider


class TestValidateIacSshSecret:
    def test_https_without_key_is_unchanged(self):
        attrs = {
            "repository_url": "https://bitbucket.org/acme/app",
            "access_token": "t",
        }
        assert validate_iac_ssh_secret(dict(attrs)) == attrs

    def test_empty_ssh_fields_are_dropped(self):
        attrs = validate_iac_ssh_secret(
            {
                "repository_url": "https://x.org/a",
                "ssh_private_key": "",
                "ssh_known_hosts": "",
            }
        )
        assert attrs == {"repository_url": "https://x.org/a"}

    def test_key_with_https_url_is_rejected(self):
        with pytest.raises(serializers.ValidationError) as error:
            validate_iac_ssh_secret(
                {
                    "repository_url": "https://bitbucket.org/acme/app",
                    "ssh_private_key": _key(),
                }
            )
        assert "ssh_private_key" in error.value.detail

    def test_ssh_url_needs_a_key(self):
        with pytest.raises(serializers.ValidationError) as error:
            validate_iac_ssh_secret({"repository_url": SSH_URL})
        assert "ssh_private_key" in error.value.detail

    def test_unreadable_key(self):
        with pytest.raises(serializers.ValidationError) as error:
            validate_iac_ssh_secret(
                {"repository_url": SSH_URL, "ssh_private_key": "nope"}
            )
        assert "ssh_private_key" in error.value.detail

    def test_pinned_host_needs_no_host_key(self):
        attrs = validate_iac_ssh_secret(
            {"repository_url": SSH_URL, "ssh_private_key": _key()}
        )
        assert "ssh_known_hosts" not in attrs

    def test_self_hosted_needs_a_host_key(self):
        with pytest.raises(serializers.ValidationError) as error:
            validate_iac_ssh_secret(
                {"repository_url": SELF_HOSTED_URL, "ssh_private_key": _key()}
            )
        assert "ssh_known_hosts" in error.value.detail
        assert "git.example.com" in str(error.value.detail["ssh_known_hosts"])

    def test_self_hosted_with_bracketed_port_host_key(self):
        attrs = validate_iac_ssh_secret(
            {
                "repository_url": SELF_HOSTED_URL,
                "ssh_private_key": _key(),
                "ssh_known_hosts": f"# scanned\n{HOST_LINE}\n",
            }
        )
        assert attrs["ssh_known_hosts"] == HOST_LINE

    def test_malformed_host_key(self):
        with pytest.raises(serializers.ValidationError) as error:
            validate_iac_ssh_secret(
                {
                    "repository_url": SELF_HOSTED_URL,
                    "ssh_private_key": _key(),
                    "ssh_known_hosts": "git.example.com",
                }
            )
        assert "ssh_known_hosts" in error.value.detail

    def test_serializer_runs_the_hook(self):
        serializer = IacProviderSecret(data={"repository_url": SSH_URL})
        assert not serializer.is_valid()
        assert "ssh_private_key" in serializer.errors

        serializer = IacProviderSecret(
            data={"repository_url": SSH_URL, "ssh_private_key": _key()}
        )
        assert serializer.is_valid(), serializer.errors

    def test_iac_ssh_kwargs(self):
        assert iac_ssh_kwargs(None) == {}
        assert iac_ssh_kwargs(
            {"access_token": "t", "ssh_private_key": "k", "ssh_known_hosts": ""}
        ) == {"ssh_private_key": "k"}


class TestTrivyRepoOverSsh:
    def test_ssh_urls_are_not_embedded_credentials(self):
        assert not _has_embedded_credentials(SSH_URL)
        assert not _has_embedded_credentials(SELF_HOSTED_URL)
        assert _has_embedded_credentials("https://jane:pw@bitbucket.org/acme/app.git")

    def test_ssh_repo_is_cloned_and_scanned_with_fs(self, tmp_path):
        provider = _iac_provider({"repository_url": SSH_URL, "ssh_private_key": _key()})

        def fake_clone(url, target, **kwargs):
            Path(target, ".git").mkdir(parents=True)
            Path(target, "main.tf").write_text("resource {}")

        with (
            patch(
                "cloudsneeker_api.services.trivy._resolve_trivy_bin",
                return_value="trivy",
            ),
            patch("dulwich.porcelain.clone", side_effect=fake_clone) as mock_clone,
        ):
            argv, _env = build_trivy_command(
                mode="repo",
                config={"repository_url": SSH_URL, "scanners": ["vuln"]},
                provider=provider,
                work_dir=tmp_path,
            )

        assert argv[-2] == "fs"
        clone_dir = Path(argv[-1])
        assert clone_dir == tmp_path / "repository"
        assert (clone_dir / "main.tf").exists()
        assert not (clone_dir / ".git").exists()
        assert mock_clone.call_args.args[0] == SSH_URL
        assert "key_filename" in mock_clone.call_args.kwargs

    def test_ssh_repo_without_key_fails(self, tmp_path):
        provider = _iac_provider({"repository_url": SSH_URL})
        with patch(
            "cloudsneeker_api.services.trivy._resolve_trivy_bin", return_value="trivy"
        ):
            with pytest.raises(TrivyHubError, match="SSH private key"):
                build_trivy_command(
                    mode="repo",
                    config={"repository_url": SSH_URL},
                    provider=provider,
                    work_dir=tmp_path,
                )

    def test_ssh_clone_error_is_actionable(self, tmp_path):
        provider = _iac_provider({"repository_url": SSH_URL, "ssh_private_key": _key()})
        with (
            patch(
                "cloudsneeker_api.services.trivy._resolve_trivy_bin",
                return_value="trivy",
            ),
            patch(
                "dulwich.porcelain.clone",
                side_effect=Exception("Permission denied (publickey)."),
            ),
        ):
            with pytest.raises(TrivyHubError, match="deploy key"):
                build_trivy_command(
                    mode="repo",
                    config={"repository_url": SSH_URL},
                    provider=provider,
                    work_dir=tmp_path,
                )


class TestSastCloneOverSsh:
    def test_clones_with_the_ssh_key(self, tmp_path):
        provider = _iac_provider({"repository_url": SSH_URL, "ssh_private_key": _key()})

        def fake_clone(url, target, **kwargs):
            Path(target, ".git").mkdir(parents=True)

        with patch("dulwich.porcelain.clone", side_effect=fake_clone) as mock_clone:
            secrets = clone_repository(SSH_URL, provider, tmp_path)

        assert secrets == ()
        assert mock_clone.call_args.args[0] == SSH_URL
        assert "ssh_command" in mock_clone.call_args.kwargs
        assert not (tmp_path / ".git").exists()

    def test_missing_key_is_reported(self, tmp_path):
        provider = _iac_provider({"repository_url": SSH_URL})
        with pytest.raises(TrivyHubError, match="SSH private key"):
            clone_repository(SSH_URL, provider, tmp_path)
