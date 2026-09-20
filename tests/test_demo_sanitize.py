"""Unit tests for demo_sanitize.py's pure functions -- no DB, no
network. `known_real_identifiers()`/`leak_scan()`/`leak_scan_hosts()`
already have integration coverage via test_demo_snapshot.py and
test_demo_host_snapshot.py (they need a real Postgres connection);
this file covers what doesn't.
"""

from invariant_contracts import Finding

from invariant_api.demo_sanitize import is_demo_endpoint, redact_real_identity, verify_redaction

_DEMO_LAB_HOSTS_NETWORK_EXAMPLES = ["10.89.77.1", "10.89.77.11", "10.89.77.254"]


def _finding_kwargs(**overrides) -> dict:
    base = dict(
        target="real-name",
        external_id="5.1.20",
        status="FAIL",
        control_title="Ensure sshd PermitRootLogin is disabled",
        source_name="cis",
        document_name="debian_linux_12",
        document_version="2.0.0",
        evidence_output="sshd_config: PermitRootLogin <not set>",
        collected_at="2026-09-20T00:00:00+00:00",
        remediation="",
        raw_artifact_path="",
        level=1,
        scored=True,
    )
    base.update(overrides)
    return base


def _finding(**overrides) -> Finding:
    return Finding(**_finding_kwargs(**overrides))


class TestIsDemoEndpoint:
    def test_addresses_inside_the_reserved_network_are_demo(self):
        for addr in _DEMO_LAB_HOSTS_NETWORK_EXAMPLES:
            assert is_demo_endpoint(addr) is True

    def test_addresses_outside_the_reserved_network_are_not_demo(self):
        assert is_demo_endpoint("172.16.2.2") is False
        assert is_demo_endpoint("10.153.120.1") is False
        assert is_demo_endpoint("8.8.8.8") is False

    def test_invalid_input_returns_false_never_raises(self):
        assert is_demo_endpoint("") is False
        assert is_demo_endpoint("not-an-ip") is False
        assert is_demo_endpoint("10.89.77.0/24") is False  # CIDR range, not a single IP
        assert is_demo_endpoint("2001:db8::1") is False  # valid IPv6, just not in the v4 reserved net


class TestRedactRealIdentity:
    def test_replaces_real_value_in_every_redactable_field_not_just_target(self):
        finding = _finding(
            target="demo-host-web-01",
            evidence_output="host demo-host-web-01 replied",
            remediation="fix demo-host-web-01's config",
            raw_artifact_path="/artifacts/demo-host-web-01.json",
        )

        redacted = redact_real_identity(finding, [("demo-host-web-01", "web-prod-03.internal")])

        assert redacted.target == "web-prod-03.internal"
        assert "demo-host-web-01" not in redacted.evidence_output
        assert "web-prod-03.internal" in redacted.evidence_output
        assert "demo-host-web-01" not in redacted.remediation
        assert "demo-host-web-01" not in redacted.raw_artifact_path

    def test_untouched_fields_are_never_redacted(self):
        finding = _finding(control_title="demo-host-web-01 in the title, should never be touched")

        redacted = redact_real_identity(finding, [("demo-host-web-01", "web-prod-03.internal")])

        assert redacted.control_title == "demo-host-web-01 in the title, should never be touched"

    def test_tolerates_none_valued_fields(self):
        # Finding's own contract types every redactable field as plain
        # `str` (Pydantic rejects None at construction) -- but the
        # isinstance guard in redact_real_identity is deliberately kept
        # anyway as defense against any future contract relaxation, so
        # this test bypasses validation (model_construct) specifically
        # to exercise that path rather than one Pydantic already blocks.
        finding = Finding.model_construct(**{**_finding_kwargs(), "raw_artifact_path": None})

        redacted = redact_real_identity(finding, [("demo-host-web-01", "web-prod-03.internal")])

        assert redacted.raw_artifact_path is None

    def test_applies_longer_replacements_before_shorter_ones(self):
        # "10.89.77.1" is a prefix of "10.89.77.11" -- applying the
        # shorter replacement first would corrupt the longer value.
        finding = _finding(evidence_output="connect from 10.89.77.11 refused")

        redacted = redact_real_identity(
            finding,
            [("10.89.77.1", "192.0.2.1"), ("10.89.77.11", "192.0.2.11")],
        )

        assert redacted.evidence_output == "connect from 192.0.2.11 refused"

    def test_empty_replacement_list_is_a_noop(self):
        finding = _finding(evidence_output="nothing to redact here")

        redacted = redact_real_identity(finding, [])

        assert redacted.evidence_output == "nothing to redact here"


class TestVerifyRedaction:
    def test_clean_snapshot_reports_no_issues(self):
        items = [{"name": "web-prod-03.internal", "address": "192.0.2.11", "findings": [_finding(target="web-prod-03.internal").model_dump(mode="json")]}]

        issues = verify_redaction(items, [("demo-host-web-01", "web-prod-03.internal")])

        assert issues == []

    def test_leftover_real_value_is_reported_as_redaction_incomplete(self):
        items = [{"name": "web-prod-03.internal", "address": "192.0.2.11", "findings": [_finding(evidence_output="oops demo-host-web-01 leaked").model_dump(mode="json")]}]

        issues = verify_redaction(items, [("demo-host-web-01", "web-prod-03.internal")])

        assert len(issues) == 1
        assert issues[0]["category"] == "redaction_incomplete"

    def test_checks_name_and_address_fields_too_not_just_findings(self):
        items = [{"name": "demo-host-web-01", "address": "192.0.2.11", "findings": []}]

        issues = verify_redaction(items, [("demo-host-web-01", "web-prod-03.internal")])

        assert any(i["field"].endswith(".name") for i in issues)
