"""Claude through Seeker AI's "OpenAI Compatible" provider.

Anthropic's OpenAI-compatible layer serves chat completions with a bearer
token, but ``GET /v1/models`` there is the native Models API: it needs
``x-api-key`` and ``anthropic-version`` and pages 20 models at a time. Without
these, the provider connection check fails with a 400 even for a valid key.
"""

from urllib.parse import urlparse

ANTHROPIC_API_HOST = "api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_MODELS_PAGE_LIMIT = 1000


def is_anthropic_base_url(base_url: str) -> bool:
    """Return True when ``base_url`` points at the Anthropic API."""
    host = (urlparse(base_url or "").hostname or "").lower()
    return host == ANTHROPIC_API_HOST


def openai_compatible_client_kwargs(base_url: str, api_key: str) -> dict:
    """Extra ``openai.OpenAI`` kwargs for the given base URL."""
    if not is_anthropic_base_url(base_url):
        return {}
    return {
        "default_headers": {
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        }
    }


def openai_compatible_models_list_kwargs(base_url: str) -> dict:
    """Extra ``client.models.list`` kwargs for the given base URL."""
    if not is_anthropic_base_url(base_url):
        return {}
    return {"extra_query": {"limit": ANTHROPIC_MODELS_PAGE_LIMIT}}
