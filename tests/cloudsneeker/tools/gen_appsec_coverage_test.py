from cloudsneeker.tools import gen_appsec_coverage


class TestCoveragePage:
    def test_committed_page_matches_the_capability_matrix(self):
        assert gen_appsec_coverage.main(["--check"]) == 0

    def test_page_lists_every_feature_with_its_status(self):
        caps = gen_appsec_coverage.load_capabilities()
        page = gen_appsec_coverage.render(caps)
        for feature in caps.FEATURES:
            assert caps.STATUS_LABELS[feature["status"]] in page
            assert " ".join(feature["feature"].split()) in page
        for label in caps.STATUS_LABELS.values():
            assert f"| {label} |" in page
        assert f"| Total | {len(caps.FEATURES)} |" in page

    def test_option_table_never_lists_an_unsupported_target(self):
        caps = gen_appsec_coverage.load_capabilities()
        page = gen_appsec_coverage.render(caps)
        row = next(
            line for line in page.splitlines() if "(`include_dev_deps`)" in line
        )
        assert row.endswith("| repo, fs |")
