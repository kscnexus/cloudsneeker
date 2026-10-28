"""Claude via the OpenAI-compatible Seeker AI provider."""

from cloudsneeker_api.llm_compat import (
    ANTHROPIC_VERSION,
    is_anthropic_base_url,
    openai_compatible_client_kwargs,
    openai_compatible_models_list_kwargs,
)

ANTHROPIC_URL = "https://api.anthropic.com/v1/"


class TestIsAnthropicBaseUrl:
    def test_matches_the_anthropic_api(self):
        assert is_anthropic_base_url(ANTHROPIC_URL)
        assert is_anthropic_base_url("https://API.ANTHROPIC.COM/v1")

    def test_ignores_other_hosts(self):
        assert not is_anthropic_base_url("https://openrouter.ai/api/v1")
        assert not is_anthropic_base_url("https://api.anthropic.com.evil.test/v1")
        assert not is_anthropic_base_url("")


class TestOpenAICompatibleKwargs:
    def test_anthropic_gets_native_headers(self):
        kwargs = openai_compatible_client_kwargs(ANTHROPIC_URL, "sk-ant-test")

        assert kwargs == {
            "default_headers": {
                "x-api-key": "sk-ant-test",
                "anthropic-version": ANTHROPIC_VERSION,
            }
        }

    def test_anthropic_lists_every_model(self):
        assert openai_compatible_models_list_kwargs(ANTHROPIC_URL) == {
            "extra_query": {"limit": 1000}
        }

    def test_other_providers_are_unchanged(self):
        url = "https://openrouter.ai/api/v1"
        assert openai_compatible_client_kwargs(url, "key") == {}
        assert openai_compatible_models_list_kwargs(url) == {}
