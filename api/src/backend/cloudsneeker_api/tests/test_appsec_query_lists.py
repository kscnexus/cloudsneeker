"""List filters of the Application Security findings query (no database)."""

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from cloudsneeker_api.appsec.queries import QueryError, facet_params, filter_findings

TARGET_A = "0b6f0f7e-2f43-4c41-9a0e-6a3f4c1f0a01"
TARGET_B = "0b6f0f7e-2f43-4c41-9a0e-6a3f4c1f0a02"
NOW = datetime(2026, 11, 12, tzinfo=UTC)


def _queryset():
    queryset = MagicMock()
    queryset.filter.return_value = queryset
    queryset.exclude.return_value = queryset
    return queryset


def _filter_kwargs(queryset):
    merged = {}
    for call in queryset.filter.call_args_list:
        merged.update(call.kwargs)
    return merged


class TestListFilters:
    def test_target_and_application_lists(self):
        queryset = _queryset()
        filter_findings(
            queryset,
            {
                "filter[target__in]": f"{TARGET_A}, {TARGET_B}",
                "filter[application__in]": TARGET_A,
            },
            now=NOW,
        )
        kwargs = _filter_kwargs(queryset)
        assert kwargs["target_id__in"] == [TARGET_A, TARGET_B]
        assert kwargs["target__application_id__in"] == [TARGET_A]

    def test_rejects_values_that_are_not_ids(self):
        with pytest.raises(QueryError, match="target__in"):
            filter_findings(_queryset(), {"filter[target__in]": "not-an-id"}, now=NOW)

    def test_single_target_filter_still_works(self):
        queryset = _queryset()
        filter_findings(queryset, {"filter[target]": TARGET_A}, now=NOW)
        assert _filter_kwargs(queryset)["target_id"] == TARGET_A


class TestCombinedFilters:
    def test_every_filter_of_a_combination_is_applied(self):
        queryset = _queryset()
        filter_findings(
            queryset,
            {
                "filter[category]": "vulnerability",
                "filter[severity__in]": "critical,high",
                "filter[state__in]": "open",
                "filter[priority__in]": "urgent,high",
                "filter[triage_status__in]": "open,under_review",
                "filter[target__in]": f"{TARGET_A},{TARGET_B}",
                "filter[target_type]": "repo,image",
                "filter[fix_available]": "true",
            },
            now=NOW,
        )
        kwargs = _filter_kwargs(queryset)
        assert kwargs["category__in"] == ["vulnerability"]
        assert kwargs["severity__in"] == ["critical", "high"]
        assert kwargs["state__in"] == ["open"]
        assert kwargs["priority__in"] == ["urgent", "high"]
        assert kwargs["triage_status__in"] == ["open", "under_review"]
        assert kwargs["target_id__in"] == [TARGET_A, TARGET_B]
        assert kwargs["target__mode__in"] == ["repo", "image"]
        assert kwargs["fix_available"] is True


class TestFacetParams:
    def test_keeps_only_the_workspace_scope(self):
        scoped = facet_params(
            {
                "filter[category]": "code",
                "filter[severity__in]": "high",
                "filter[target__in]": TARGET_A,
                "filter[target_type]": "repo",
                "filter[application__in]": TARGET_B,
            }
        )
        assert scoped == {
            "filter[category]": "code",
            "filter[state__in]": "new,open,reopened,fixed",
            "filter[suppressed]": "any",
        }

    def test_without_a_category_covers_every_finding(self):
        assert "filter[category]" not in facet_params({"filter[search]": "x"})
