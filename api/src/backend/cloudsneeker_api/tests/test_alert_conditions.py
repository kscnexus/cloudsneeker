from cloudsneeker_api.services.alert_conditions import evaluate_condition, preview_condition


class _FakeQuerySet(list):
    def filter(self, **kwargs):
        items = self
        if "severity__in" in kwargs:
            allowed = set(kwargs["severity__in"])
            items = [item for item in self if item["severity"] in allowed]
        if "severity" in kwargs:
            items = [item for item in self if item["severity"] == kwargs["severity"]]
        return _FakeQuerySet(items)

    def exclude(self, **kwargs):
        if "id__in" in kwargs:
            blocked = set(kwargs["id__in"])
            return _FakeQuerySet([item for item in self if item["id"] not in blocked])
        return _FakeQuerySet(self)

    def exists(self):
        return bool(self)

    def count(self):
        return len(self)

    def values_list(self, *fields, flat=False):
        if flat and len(fields) == 1:
            return [item[fields[0]] for item in self]
        return [tuple(item[field] for field in fields) for item in self]

    def __getitem__(self, item):
        result = list.__getitem__(self, item)
        return _FakeQuerySet(result) if isinstance(item, slice) else result


def test_count_gte_condition_matches():
    findings = _FakeQuerySet(
        [
            {"id": "1", "severity": "critical"},
            {"id": "2", "severity": "low"},
        ]
    )
    matched, queryset = evaluate_condition(
        findings,
        {"op": "count_gte", "filter": {"severity": ["critical"]}, "value": 1},
    )
    assert matched is True
    assert queryset.count() == 1


def test_preview_condition_summarizes_severity():
    findings = _FakeQuerySet(
        [
            {"id": "1", "severity": "critical"},
            {"id": "2", "severity": "critical"},
            {"id": "3", "severity": "high"},
        ]
    )
    preview = preview_condition(
        findings,
        {"op": "any", "filter": {"severity": ["critical", "high"]}},
    )
    assert preview["evaluation_failed"] is False
    assert preview["summary"]["finding_count_total"] == 3
    assert preview["summary"]["counts_by_severity"]["critical"] == 2
