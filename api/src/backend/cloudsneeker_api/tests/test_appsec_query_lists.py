"""List filters of the Application Security findings query (no database)."""

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from cloudsneeker_api.appsec.queries import QueryError, filter_findings

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
