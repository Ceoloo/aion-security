import json
from pathlib import Path

import pytest

from aion_security.blue import control_for, run_check
from aion_security.blue.checks import IdpMfaCheck
from aion_security.cli import main
from aion_security.connectors import FileIdentityConnector
from aion_security.contracts import ControlRef, RiskTier, RunStatus, Severity
from aion_security.runtime_client import RuntimeClient, UnpinnedControlError

FIXTURE = Path(__file__).parent / "fixtures" / "idp_export.json"
PINNED = ControlRef("CA-TEST-001", "1.0.0")


def _run(path=FIXTURE, control=PINNED):
    return run_check(IdpMfaCheck(FileIdentityConnector(path)), control)


def test_scope_and_outcomes():
    r = _run()
    assert r.status is RunStatus.FAIL
    # 5 active humans in scope; suspended + service account excluded.
    assert r.evaluated == 5
    assert r.passed == 2
    by_subject = {f.subject: f for f in r.findings}
    assert set(by_subject) == {"u-weak", "u-admin-none", "u-none"}
    assert by_subject["u-weak"].severity is Severity.MEDIUM
    assert by_subject["u-none"].severity is Severity.HIGH
    assert by_subject["u-admin-none"].severity is Severity.CRITICAL


def test_proposals_are_gated_and_privileged_is_r3():
    r = _run()
    tiers = {p.subject: p.risk_tier for p in r.proposals}
    assert tiers == {"u-weak": RiskTier.R2, "u-none": RiskTier.R2, "u-admin-none": RiskTier.R3}
    assert all(p.requires_human_approval for p in r.proposals)


def test_evidence_is_deterministic():
    a, b = _run(), _run()
    assert a.evidence.snapshot_sha256 == b.evidence.snapshot_sha256
    assert a.evidence.subject_count == 7


def test_all_strong_passes(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"identities": [
        {"id": "a", "username": "a", "kind": "human", "status": "active", "mfa_factors": ["webauthn"]}
    ]}))
    r = _run(p)
    assert r.status is RunStatus.PASS and not r.findings and not r.proposals


@pytest.mark.parametrize("doc", [
    "not json",
    json.dumps({"users": []}),
    json.dumps({"identities": [{"id": "a"}]}),
    json.dumps({"identities": [{"id": "a", "username": "a", "kind": "robot", "status": "active"}]}),
])
def test_bad_observation_fails_closed(tmp_path, doc):
    p = tmp_path / "x.json"
    p.write_text(doc)
    r = _run(p)
    assert r.status is RunStatus.ERROR
    assert r.evidence is None and r.error


def test_default_pin_is_unpinned_and_blocks_reporting():
    control = control_for("idp-mfa")
    assert not control.pinned
    r = _run(control=control)
    calls = []
    client = RuntimeClient("http://rt", transport=lambda *a: calls.append(a) or (200, b"{}"))
    with pytest.raises(UnpinnedControlError):
        client.report_run(r)
    with pytest.raises(UnpinnedControlError):
        client.propose(r.proposals[0], r)
    assert calls == []


def test_runtime_payloads():
    r = _run()
    calls = []

    def transport(method, url, headers, body):
        calls.append((method, url, headers, json.loads(body)))
        return 202, b'{"id": "x"}'

    client = RuntimeClient("http://rt/", token="t", transport=transport)
    client.report_run(r)
    client.propose(r.proposals[0], r)

    (m1, u1, h1, b1), (m2, u2, h2, b2) = calls
    assert (m1, u1) == ("POST", "http://rt/v1/assurance/runs")
    assert b1["control"] == {"id": "CA-TEST-001", "version": "1.0.0"}
    assert b1["status"] == "fail"
    assert h1["Authorization"] == "Bearer t" and h1["Idempotency-Key"]
    assert u2 == "http://rt/v1/commands"
    assert b2["mode"] == "propose" and b2["requires_human_approval"] is True
    assert b2["source"]["evidence_sha256"] == r.evidence.snapshot_sha256


def test_cli_dry_run(capsys):
    assert main(["blue", "run", "idp-mfa", "--idp-export", str(FIXTURE)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["check"] == "idp-mfa" and len(out["findings"]) == 3
    assert "runtime" not in out


def test_cli_report_refuses_unpinned(capsys):
    rc = main(["blue", "run", "idp-mfa", "--idp-export", str(FIXTURE), "--report", "--runtime-url", "http://127.0.0.1:9"])
    assert rc == 2
    assert "no pinned CA control" in capsys.readouterr().err
