"""Seeker AI drafting of dry-run governance policies.

The tenant's Seeker AI LLM configuration (``LighthouseTenantConfiguration`` and
``LighthouseProviderConfiguration``) is reused as-is. A draft is only returned
as valid after the same checks a saved policy goes through: YAML structure, no
actions, resource prefix matching the cloud, and the engine's own validator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml
from api.db_utils import rls_transaction
from api.models import (
    LighthouseProviderConfiguration,
    LighthouseProviderModels,
    LighthouseTenantConfiguration,
)
from cloudsneeker_api.services.brand_text import scrub_engine_text
from cloudsneeker_api.services.custodian import (
    CustodianDryRunError,
    assert_policy_matches_provider,
)
from cloudsneeker_api.services.custodian_library import (
    list_library_policies,
    render_policy_yaml,
)
from cloudsneeker_api.services.custodian_validate import (
    validate_custodian_policy_schema,
)

GENERATE_PROVIDERS = ("aws", "azure", "gcp")
MAX_PROMPT_LENGTH = 2000
MAX_COMPLETION_TOKENS = 2000
# One repair round: the validator's message goes back to the model once.
MAX_ATTEMPTS = 2

_FENCE = re.compile(r"```(?:ya?ml)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_NAME_CHARS = re.compile(r"[^a-z0-9]+")
_RESOURCE = re.compile(r"^[a-z0-9]+\.[a-z0-9-]+$")


class PolicyGenerationError(Exception):
    """Raised when Seeker AI cannot be reached or is not configured."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class LLMSettings:
    """The tenant's chosen Seeker AI provider and model."""

    provider_type: str
    model_id: str
    config: LighthouseProviderConfiguration


def resolve_llm_settings(tenant_id: str) -> LLMSettings:
    """Pick the tenant's default Seeker AI provider and model.

    Raises:
        PolicyGenerationError: When no active provider or model is configured.
    """
    with rls_transaction(tenant_id):
        tenant_config = LighthouseTenantConfiguration.objects.filter(
            tenant_id=tenant_id
        ).first()
        configs = list(
            LighthouseProviderConfiguration.objects.filter(
                tenant_id=tenant_id, is_active=True
            ).order_by("inserted_at")
        )
        if not configs:
            raise PolicyGenerationError(
                "Seeker AI is not set up. Add an LLM provider in Seeker AI settings first.",
                code="llm_not_configured",
            )
        default_provider = getattr(tenant_config, "default_provider", "") or ""
        default_models = getattr(tenant_config, "default_models", None) or {}
        config = next(
            (item for item in configs if item.provider_type == default_provider),
            configs[0],
        )
        model_id = default_models.get(config.provider_type) or (
            LighthouseProviderModels.objects.filter(provider_configuration=config)
            .order_by("model_id")
            .values_list("model_id", flat=True)
            .first()
        )
    if not model_id:
        raise PolicyGenerationError(
            "Seeker AI has no model selected. Pick a default model in Seeker AI settings.",
            code="llm_not_configured",
        )
    return LLMSettings(
        provider_type=config.provider_type, model_id=model_id, config=config
    )


def complete_chat(settings: LLMSettings, messages: list[dict[str, str]]) -> str:
    """Send ``messages`` to the configured LLM and return the reply text.

    Raises:
        PolicyGenerationError: When credentials are missing or the call fails.
    """
    # Upstream owns these helpers; reuse them so credential handling and the
    # OpenAI-compatible network guard match the Seeker AI settings checks.
    from tasks.jobs import lighthouse_providers as llm

    provider_type = settings.provider_type
    try:
        if provider_type == LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK:
            creds = llm._extract_bedrock_credentials(settings.config)
            if not creds:
                raise _missing_credentials()
            return _bedrock_chat(
                llm._create_bedrock_client(creds, service_name="bedrock-runtime"),
                settings.model_id,
                messages,
            )

        import openai

        if (
            provider_type
            == LighthouseProviderConfiguration.LLMProviderChoices.OPENAI_COMPATIBLE
        ):
            params = llm._extract_openai_compatible_params(settings.config)
            if not params:
                raise _missing_credentials()
            from cloudsneeker_api.llm_compat import openai_compatible_client_kwargs

            with llm._create_openai_compatible_http_client() as http_client:
                client = openai.OpenAI(
                    api_key=params["api_key"],
                    base_url=params["base_url"],
                    http_client=http_client,
                    **openai_compatible_client_kwargs(
                        params["base_url"], params["api_key"]
                    ),
                )
                response = client.chat.completions.create(
                    model=settings.model_id,
                    messages=messages,
                    max_tokens=MAX_COMPLETION_TOKENS,
                )
            return response.choices[0].message.content or ""

        api_key = llm._extract_openai_api_key(settings.config)
        if not api_key:
            raise _missing_credentials()
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=settings.model_id,
            messages=messages,
            max_completion_tokens=MAX_COMPLETION_TOKENS,
        )
        return response.choices[0].message.content or ""
    except PolicyGenerationError:
        raise
    except Exception as exc:  # noqa: BLE001 - provider SDKs raise many types
        detail = llm._extract_error_message(exc)
        raise PolicyGenerationError(
            f"Seeker AI could not draft the policy: {detail}"[:500],
            code="llm_error",
        ) from exc


def _missing_credentials() -> PolicyGenerationError:
    return PolicyGenerationError(
        "Seeker AI credentials are incomplete. Check the provider in Seeker AI settings.",
        code="llm_not_configured",
    )


def _bedrock_chat(client: Any, model_id: str, messages: list[dict[str, str]]) -> str:
    system = [{"text": item["content"]} for item in messages if item["role"] == "system"]
    conversation = [
        {"role": item["role"], "content": [{"text": item["content"]}]}
        for item in messages
        if item["role"] != "system"
    ]
    response = client.converse(
        modelId=model_id,
        system=system,
        messages=conversation,
        inferenceConfig={"maxTokens": MAX_COMPLETION_TOKENS},
    )
    blocks = response.get("output", {}).get("message", {}).get("content", [])
    return "".join(block.get("text", "") for block in blocks)


def build_messages(
    *, provider_type: str, prompt: str, resource_type: str = ""
) -> list[dict[str, str]]:
    """Build the system prompt, two library examples, and the user request."""
    examples = _examples_for(provider_type, resource_type)
    example_text = "\n".join(item["policy_yaml"] for item in examples)
    resource_line = (
        f"Use the resource type `{resource_type}`.\n" if resource_type else ""
    )
    system = (
        "You write cloud governance policies in the Cloud Custodian YAML format. "
        "The policies only report matching resources; they never change anything.\n"
        "Rules:\n"
        "- Output exactly one YAML document in a ```yaml fenced block and nothing else.\n"
        "- The document has a top-level `policies` list with exactly one policy.\n"
        f"- `resource` must be a {provider_type} resource type starting with `{provider_type}.`.\n"
        "- Give the policy a lowercase hyphenated `name` and a one-sentence `description`.\n"
        "- Never include `actions`, `mode`, or `notify` keys.\n"
        "- Prefer `type: value` filters on documented API attributes; use only filter "
        "types that exist for that resource.\n"
        "Examples of valid policies:\n"
        f"{example_text}"
    )
    user = f"{resource_line}Write a policy that finds: {prompt.strip()}"
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _examples_for(provider_type: str, resource_type: str) -> list[dict[str, Any]]:
    entries = list_library_policies(provider_type=provider_type)
    matching = [item for item in entries if item["resource"] == resource_type]
    others = [item for item in entries if item["resource"] != resource_type]
    return (matching + others)[:2]


def extract_policy_yaml(reply: str) -> str:
    """Pull the YAML document out of an LLM reply."""
    match = _FENCE.search(reply or "")
    text = match.group(1) if match else (reply or "")
    return text.strip() + "\n"


def normalize_policy_yaml(policy_yaml: str) -> tuple[str, dict[str, Any]]:
    """Keep only the first policy, drop mutating keys, and re-render it.

    Returns:
        The normalized YAML and the policy mapping.

    Raises:
        CustodianDryRunError: When the text is not a policy document.
    """
    try:
        parsed = yaml.safe_load(policy_yaml)
    except yaml.YAMLError as exc:
        raise CustodianDryRunError(f"Invalid YAML: {exc}") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("policies"), list):
        raise CustodianDryRunError("The draft has no policies list.")
    if not parsed["policies"] or not isinstance(parsed["policies"][0], dict):
        raise CustodianDryRunError("The draft has no policy.")
    policy = {
        key: value
        for key, value in parsed["policies"][0].items()
        if key not in ("actions", "mode", "notify")
    }
    policy["name"] = _slug(str(policy.get("name") or "seeker-ai-policy"))
    return render_policy_yaml(policy), policy


def _slug(value: str) -> str:
    slug = _NAME_CHARS.sub("-", value.lower()).strip("-")
    if not slug or not slug[0].isalpha():
        slug = f"policy-{slug}".strip("-")
    return slug[:64]


def validate_draft(policy_yaml: str, provider_type: str) -> str:
    """Return an empty string when valid, otherwise a user-facing reason."""
    try:
        assert_policy_matches_provider(policy_yaml, provider_type)
        validate_custodian_policy_schema(policy_yaml)
    except CustodianDryRunError as exc:
        return scrub_engine_text(str(exc))
    return ""


def generate_policy_draft(
    *,
    tenant_id: str,
    provider_type: str,
    prompt: str,
    resource_type: str = "",
) -> dict[str, Any]:
    """Ask Seeker AI for a policy and validate it, with one repair round.

    Returns:
        ``policy_yaml``, ``name``, ``description``, ``resource``, ``valid``,
        ``validation_error`` and ``attempts``. An invalid draft is still
        returned so the user can fix it by hand.

    Raises:
        PolicyGenerationError: When Seeker AI is not configured or fails.
    """
    settings = resolve_llm_settings(tenant_id)
    messages = build_messages(
        provider_type=provider_type, prompt=prompt, resource_type=resource_type
    )
    policy_yaml = ""
    policy: dict[str, Any] = {}
    error = ""
    attempts = 0
    for attempts in range(1, MAX_ATTEMPTS + 1):
        reply = complete_chat(settings, messages)
        raw_yaml = extract_policy_yaml(reply)
        try:
            policy_yaml, policy = normalize_policy_yaml(raw_yaml)
        except CustodianDryRunError as exc:
            policy_yaml, policy = raw_yaml, {}
            error = scrub_engine_text(str(exc))
        else:
            error = validate_draft(policy_yaml, provider_type)
        if not error:
            break
        messages = [
            *messages,
            {"role": "assistant", "content": reply},
            {
                "role": "user",
                "content": (
                    f"That policy failed validation: {error}\n"
                    "Return a corrected policy in the same format."
                ),
            },
        ]

    return {
        "policy_yaml": policy_yaml,
        "name": str(policy.get("name") or ""),
        "description": str(policy.get("description") or ""),
        "resource": str(policy.get("resource") or ""),
        "provider_type": provider_type,
        "valid": not error,
        "validation_error": error,
        "attempts": attempts,
    }


def is_valid_resource_type(value: str, provider_type: str) -> bool:
    """Return True for an empty value or ``<provider>.<resource>``."""
    if not value:
        return True
    return bool(_RESOURCE.match(value)) and value.startswith(f"{provider_type}.")
