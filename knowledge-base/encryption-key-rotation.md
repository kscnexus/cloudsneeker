# Encryption Key Rotation

Stored secrets are encrypted with one Fernet key, `DJANGO_SECRETS_ENCRYPTION_KEY`. They include cloud provider credentials, integration credentials (S3, Security Hub, Jira, Slack), LLM keys, tenant SMTP passwords, Slack app secrets and MFA secrets. This runbook replaces that key without downtime (EB-016).

## How it works

* `cloudsneeker_api/crypto.py` builds a `MultiFernet`. It encrypts with `DJANGO_SECRETS_ENCRYPTION_KEY` and still decrypts with every key in `DJANGO_SECRETS_ENCRYPTION_KEY_PREVIOUS` (comma-separated). The hook is the `fernet = build_fernet(...)` line in `api/models.py`.
* `manage.py cloudsneeker_rotate_secrets` re-encrypts every stored value that only a previous key can read. With `--check` it only reports, and it fails while any value still needs a previous key. Values are never printed. The fields it covers are listed in `cloudsneeker_api/services/secret_rotation.py` (`ENCRYPTED_FIELDS`). Add any new encrypted field there.
* API keys use their own key, `DJANGO_API_KEY_FERNET_SECRET`. `deploy.ps1` pins it to the original data key. Rotating the data key does not revoke API keys.

On the hosted stack the values live in Secrets Manager secret `cloudsneeker/app`:

| Secret key | Environment variable | Tasks |
| --- | --- | --- |
| `djangoSecretsEncryptionKey` | `DJANGO_SECRETS_ENCRYPTION_KEY` | api, worker, beat |
| `djangoSecretsEncryptionKeyPrevious` | `DJANGO_SECRETS_ENCRYPTION_KEY_PREVIOUS` (`unconfigured` = none) | api, worker, beat |
| `djangoApiKeyFernetSecret` | `DJANGO_API_KEY_FERNET_SECRET` | api |

## Rotate

Keep a copy of the current key until step 6 passes. Losing it before then makes the secrets it encrypted unreadable.

1. Generate a key:

   ```bash
   python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
   ```

2. In `cloudsneeker/app`, set `djangoSecretsEncryptionKeyPrevious` to the current `djangoSecretsEncryptionKey`. Then set `djangoSecretsEncryptionKey` to the new key. Leave `djangoApiKeyFernetSecret` alone.

3. Restart the tasks so they read the secret. New values are encrypted with the new key from here on, and old values still read.

   ```bash
   for s in api worker beat; do aws ecs update-service --profile kscnexus --region us-east-1 --cluster cloudsneeker --service $s --force-new-deployment > /dev/null; done
   aws ecs wait services-stable --profile kscnexus --region us-east-1 --cluster cloudsneeker --services api worker beat
   ```

4. Run `cloudsneeker_rotate_secrets` as a one-off task. Register `cloudsneeker-api-oneoff` from the current API task definition first, as in [operator-console.md](operator-console.md) step 1. Register it again after step 3 so it picks up the new task definition revision.

   ```powershell
   aws ecs run-task --profile kscnexus --region us-east-1 `
     --cluster cloudsneeker --task-definition cloudsneeker-api-oneoff `
     --launch-type FARGATE `
     --network-configuration "awsvpcConfiguration={subnets=[<subnet-a>,<subnet-b>],securityGroups=[<api-sg>],assignPublicIp=DISABLED}" `
     --overrides '{"containerOverrides":[{"name":"api","command":["cloudsneeker_rotate_secrets"]}]}'
   ```

   Read the log stream `oneoff/api/<task id>` in `/ecs/cloudsneeker/api`. Each field prints `current`, `stale`, `rotated` and `unreadable`. If anything is `unreadable`, it was written with a key that is not configured. Add that key to `djangoSecretsEncryptionKeyPrevious`, then repeat steps 3 and 4.

5. Run the same task with `["cloudsneeker_rotate_secrets", "--check"]`. It must end with "All stored secrets use the current key."

6. Set `djangoSecretsEncryptionKeyPrevious` back to `unconfigured` and repeat step 3. Delete the old key copy.

7. Run step 5 again. Then make an end-to-end check: a provider connection test and an integration test from the app.

## Notes

* A stack restored from a backup taken before step 6 needs the old key again. Keep it with the backup until the backup expires.
* `deploy.ps1` adds the two rotation keys to older secrets on its next run. It never changes their values after that.
* Upstream migration `api/0050_lighthouse_multi_llm` builds its own `Fernet` from the current key. It has already run on every existing database. A new database runs it before any secret exists.
