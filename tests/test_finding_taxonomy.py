from invariant_contracts import Finding

from invariant_api.finding_taxonomy import classify_domain, classify_environment, ssh_state


def _finding(**overrides) -> Finding:
    defaults = dict(
        target="tamois",
        external_id="5.1.20",
        status="FAIL",
        control_title="Ensure sshd PermitRootLogin is disabled",
        source_name="cis",
        document_name="debian_linux_12",
        document_version="2.0.0",
        evidence_output="",
        collected_at="2026-09-13T00:00:00+00:00",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_classify_domain_matches_ssh():
    assert classify_domain("Ensure sshd PermitRootLogin is disabled") == "SSH Hardening"


def test_classify_domain_matches_authentication():
    assert classify_domain("Ensure pam_pwquality module is enabled") == "Authentication & PAM"


def test_classify_domain_falls_back_to_other():
    assert classify_domain("Some completely unrelated control title") == "Other"


def test_classify_environment_host_only_control_from_the_real_map():
    # (debian_linux_12, 1.4.1) is a real entry in HOST_ONLY_CONTROLS,
    # queried from the actual ingested benchmark -- "Ensure bootloader
    # password is set".
    finding = _finding(document_name="debian_linux_12", external_id="1.4.1")

    assert classify_environment(finding) == "host_only"


def test_classify_environment_is_keyed_by_document_and_external_id_not_title():
    # Same external_id as a real host-only entry, but a *different*
    # document -- must not match. Environment classification must never
    # fall back to title substring matching.
    finding = _finding(document_name="some_other_document", external_id="1.4.1")

    assert classify_environment(finding) == "container_relevant"


def test_classify_environment_defaults_to_container_relevant():
    # A control never reviewed for applicability (not in the map) must
    # default to container_relevant -- an unreviewed control must never
    # silently disappear from the report.
    finding = _finding(document_name="debian_linux_12", external_id="5.1.20")

    assert classify_environment(finding) == "container_relevant"


def test_classify_environment_does_not_depend_on_finding_status():
    # A host-only control that happens to PASS is still host_only -- this
    # is the exact bug the environment classification exists to avoid
    # ("N/A must exclude PASS too, not just FAIL").
    passed = _finding(document_name="debian_linux_12", external_id="1.4.1", status="PASS")
    failed = _finding(document_name="debian_linux_12", external_id="1.4.1", status="FAIL")

    assert classify_environment(passed) == "host_only"
    assert classify_environment(failed) == "host_only"


def test_classify_domain_matches_ssh_host_key_titles():
    # Uses "SSH" (not "sshd") -- was misclassified as "Other" before the
    # domain keyword list gained "ssh ".
    assert classify_domain("Ensure access to SSH private host key files is configured") == "SSH Hardening"
    assert classify_domain("Ensure access to SSH public host key files is configured") == "SSH Hardening"


def test_classify_domain_matches_account_session_management():
    assert classify_domain("Ensure default user umask is configured") == "Account & Session Management"
    assert classify_domain("Ensure accounts without a valid login shell are locked") == "Account & Session Management"


def test_ssh_state_absent_when_evidence_carries_the_sentinel():
    findings = [_finding(evidence_output="sshd_config: PermitRootLogin <sshd-not-installed>")]
    assert ssh_state(findings) == "absent"


def test_ssh_state_unknown_when_evidence_carries_that_sentinel():
    findings = [_finding(evidence_output="sshd_config: PermitRootLogin <sshd-status-unknown>")]
    assert ssh_state(findings) == "unknown"


def test_ssh_state_present_when_evidence_shows_a_real_value():
    findings = [_finding(evidence_output="sshd_config: PermitRootLogin no")]
    assert ssh_state(findings) == "present"


def test_ssh_state_defaults_to_present_with_no_sshd_evidence_at_all():
    findings = [_finding(evidence_output="/etc/shadow: mode=0o640 uid=0 gid=42")]
    assert ssh_state(findings) == "present"


def test_ssh_state_never_calls_classify_domain(monkeypatch):
    # SSH applicability must never depend on the cosmetic domain
    # classifier -- if it did, this would raise instead of returning
    # normally.
    import invariant_api.finding_taxonomy as taxonomy

    def _boom(_title):
        raise AssertionError("ssh_state must not call classify_domain")

    monkeypatch.setattr(taxonomy, "classify_domain", _boom)
    findings = [_finding(evidence_output="sshd_config: PermitRootLogin <sshd-not-installed>")]

    assert taxonomy.ssh_state(findings) == "absent"
