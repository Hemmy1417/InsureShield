"""The adversarial suite: every legitimate and adversarial fixture case,
the on-chain adversarial-test engine, and the attacks that need more than
one step (evidence shopping, relocation, double-dipping, relabelling).

Model-decided cases here prove what the contract DOES with a panel answer -
grounding, downgrades, precedence - not that a real model gives that
answer. Real-model behaviour is shown only by the live run (docs/DEPLOYMENT.md).
"""

import json

import pytest

from tests.direct.support import (
    ADVERSARIAL, BASE, LEGITIMATE, NOW, TRUSTED_PREFIX, case, evidence_lists,
    finding, mock_documents, mock_panel, panel_answer, present, run_case,
    stage, submit, warp,
)

ALL_CASES = [c["case_id"] for c in LEGITIMATE["cases"] + ADVERSARIAL["cases"]]
STANDALONE = [c for c in ALL_CASES if "requires_prior" not in case(c)]
WITH_PRIOR = [c for c in ALL_CASES if "requires_prior" in case(c)]


def check_expectations(entry: dict, receipt: dict):
    assert receipt["verdict"] == entry["expected_outcome"], receipt["reason_codes"]
    for indicator in entry["expected_indicators"]:
        assert indicator in present(receipt), (indicator, present(receipt))
    decided = entry["decided_by"]
    if decided == "ADMISSION":
        assert receipt["deterministic_only"] is True
        assert any(r.startswith("ADMISSION:") for r in receipt["reason_codes"])
        assert receipt["rows"] == [] and receipt["criteria"] == []
    elif entry["panel"] is None:
        assert receipt["deterministic_only"] is False
        assert receipt["panel_state"] == "SKIPPED"
    else:
        assert receipt["panel_state"] == "ASSESSED"
    if decided == "REGISTRY":
        registry = [f for f in receipt["indicators"] if f["by"] == "REGISTRY"
                    and f["state"] == "PRESENT"]
        assert registry, receipt["indicators"]


@pytest.mark.parametrize("case_id", STANDALONE)
def test_fixture_case(shield, direct_vm, policy_id, case_id):
    entry = case(case_id)
    _claim_id, receipt = run_case(shield, direct_vm, policy_id, case_id)
    check_expectations(entry, receipt)


@pytest.mark.parametrize("case_id", WITH_PRIOR)
def test_fixture_case_after_its_prior_claim(shield, direct_vm, direct_bob,
                                            policy_id, case_id):
    entry = case(case_id)
    with direct_vm.prank(direct_bob):
        _prior, prior_receipt = run_case(shield, direct_vm, policy_id,
                                         entry["requires_prior"])
    assert prior_receipt["verdict"] == "VALID"
    _claim_id, receipt = run_case(shield, direct_vm, policy_id, case_id)
    check_expectations(entry, receipt)


def test_code_decided_findings_in_panel_cases(shield, direct_vm, policy_id):
    """A-09: the untrusted ownership record is never offered to the panel
    for the trusted-only criterion - the panel's SATISFIED answer for C4 is
    in the mock and is ignored."""
    entry = case("A-09")
    claim_id = submit(shield, policy_id, entry["claim"])
    answer = panel_answer(entry)
    answer["criteria"]["C4"] = panel_answer(case("L-01"))["criteria"]["C4"]
    direct_vm.clear_mocks()
    mock_documents(direct_vm, entry["claim"])
    mock_panel(direct_vm, answer)
    shield.resolve_claim(claim_id)
    receipt = shield.get_receipt(claim_id + "-R1")
    c4 = finding(receipt, "criteria", "C4")
    assert (c4["state"], c4["by"]) == ("UNVERIFIABLE", "CODE")
    assert receipt["failure_class"] == "INSUFFICIENT_EVIDENCE"


def test_missing_evidence_is_code_decided(shield, direct_vm, policy_id):
    _c, receipt = run_case(shield, direct_vm, policy_id, "A-14")
    c4 = finding(receipt, "criteria", "C4")
    assert (c4["state"], c4["by"]) == ("UNVERIFIABLE", "CODE")
    assert finding(receipt, "indicators", "OWNERSHIP_MISMATCH")["state"] == \
        "NOT_APPLICABLE"


def test_hash_mismatch_is_evidence_changed_not_fraud(shield, direct_vm, policy_id):
    _c, receipt = run_case(shield, direct_vm, policy_id, "A-16")
    assert receipt["failure_class"] == "EVIDENCE_CHANGED"
    assert [r["status"] for r in receipt["rows"]] == \
        ["EXAMINED", "EXAMINED", "HASH_MISMATCH", "EXAMINED"]
    assert receipt["rows"][2]["byte_count"] == 0
    assert present(receipt) == []
    assert receipt["severity"] == "LOW"


def test_unreachable_row_and_reachability(shield, direct_vm, policy_id):
    _c, receipt = run_case(shield, direct_vm, policy_id, "A-15")
    assert receipt["rows"][5] == {"evidence_id": "E6", "status": "UNAVAILABLE",
                                  "byte_count": 0}
    assert receipt["source_reachability"] == "PARTIAL"
    assert receipt["panel_reason"] == "EVIDENCE_NOT_EXAMINED"
    assert receipt["confidence_band"] == "LOW"


def test_nothing_reachable_is_unreachable(shield, direct_vm, policy_id):
    entry = case("L-01")
    claim_id = submit(shield, policy_id, entry["claim"])
    direct_vm.clear_mocks()
    assert shield.resolve_claim(claim_id) == "UNAVAILABLE"
    receipt = shield.get_receipt(claim_id + "-R1")
    assert receipt["source_reachability"] == "UNREACHABLE"
    assert receipt["facts"] == [] and receipt["markers"] == []
    for name in ("DUPLICATE_EVIDENCE", "DUPLICATE_DOCUMENT", "AMOUNT_INFLATED",
                 "ARITHMETIC_MISMATCH", "INJECTION_MARKER"):
        assert finding(receipt, "indicators", name)["state"] == "UNDETERMINED"


def test_an_excluded_invoice_never_falls_back_to_the_estimate(shield, direct_vm,
                                                              policy_id):
    """A-16 excludes the invoice. The claim (4,385.00) exceeds the estimate
    (4,120.00), but comparing against the estimate alone would be a sum over
    part of the record: AMOUNT_INFLATED is UNDETERMINED, not PRESENT."""
    _c, receipt = run_case(shield, direct_vm, policy_id, "A-16")
    assert finding(receipt, "indicators", "AMOUNT_INFLATED")["state"] == \
        "UNDETERMINED"
    assert finding(receipt, "criteria", "C2")["state"] == "UNVERIFIABLE"


def test_malformed_structured_document_is_unparseable(shield, direct_vm, policy_id):
    _c, receipt = run_case(shield, direct_vm, policy_id, "A-18")
    assert receipt["rows"][1]["status"] == "UNPARSEABLE"
    assert receipt["rows"][1]["byte_count"] > 0
    assert receipt["facts"] == []
    assert receipt["failure_class"] == "EVIDENCE_MALFORMED"


def test_oversized_document_is_too_large(shield, direct_vm, policy_id):
    entry = case("L-01")
    big = b"x" * 12001
    kinds, urls, hashes = evidence_lists(entry["claim"])
    hashes[4] = __import__("hashlib").sha256(big).hexdigest()
    claim_id = submit(shield, policy_id, entry["claim"],
                      lists=(kinds, urls, hashes))
    direct_vm.clear_mocks()
    mock_documents(direct_vm, entry["claim"],
                   bodies={"evidence/legit/witness_statement.txt": big})
    assert shield.resolve_claim(claim_id) == "INCONCLUSIVE"
    receipt = shield.get_receipt(claim_id + "-R1")
    assert receipt["rows"][4] == {"evidence_id": "E5", "status": "TOO_LARGE",
                                  "byte_count": 12001}


def test_non_utf8_text_is_unparseable(shield, direct_vm, policy_id):
    entry = case("L-01")
    body = b"\xff\xfe witness"
    kinds, urls, hashes = evidence_lists(entry["claim"])
    hashes[4] = __import__("hashlib").sha256(body).hexdigest()
    claim_id = submit(shield, policy_id, entry["claim"],
                      lists=(kinds, urls, hashes))
    direct_vm.clear_mocks()
    mock_documents(direct_vm, entry["claim"],
                   bodies={"evidence/legit/witness_statement.txt": body})
    shield.resolve_claim(claim_id)
    assert shield.get_receipt(claim_id + "-R1")["rows"][4]["status"] == \
        "UNPARSEABLE"


# -- the ambiguous exclusion: grounded either way, never ungrounded ---------------

def ambiguous_with(direct_vm, shield, policy_id, x1: dict) -> dict:
    entry = case("A-17")
    claim_id = submit(shield, policy_id, entry["claim"])
    answer = panel_answer(entry)
    answer["exclusions"]["X1"] = x1
    direct_vm.clear_mocks()
    mock_documents(direct_vm, entry["claim"])
    mock_panel(direct_vm, answer)
    shield.resolve_claim(claim_id)
    return shield.get_receipt(claim_id + "-R1")


def test_ambiguous_exclusion_applies_only_with_a_quote(shield, direct_vm, policy_id):
    receipt = ambiguous_with(direct_vm, shield, policy_id, {
        "state": "APPLIES", "evidence_ids": ["E1"], "quotes": [], "note": ""})
    x1 = finding(receipt, "exclusions", "X1")
    assert x1["state"] == "UNVERIFIABLE"
    assert receipt["verdict"] == "INCONCLUSIVE"


def test_ambiguous_exclusion_read_as_unverifiable(shield, direct_vm, policy_id):
    receipt = ambiguous_with(direct_vm, shield, policy_id, {
        "state": "UNVERIFIABLE", "evidence_ids": [], "quotes": [], "note": ""})
    assert receipt["verdict"] == "INCONCLUSIVE"


def test_ambiguous_exclusion_read_as_not_applying(shield, direct_vm, policy_id):
    receipt = ambiguous_with(direct_vm, shield, policy_id, {
        "state": "DOES_NOT_APPLY", "evidence_ids": ["E1"], "quotes": [],
        "note": "The shift had ended and the app was off."})
    assert receipt["verdict"] == "VALID"


# -- multi-step attacks ------------------------------------------------------------

def test_evidence_shopping_cannot_withdraw_a_contradiction(shield, direct_vm,
                                                           policy_id):
    """A-07 is INCONCLUSIVE because a witness contradicts the report. There is
    no way to remove that witness: a retry can only add or relocate, and
    relocating its sha256 onto the friendlier statement's URL just fails the
    hash check - UNAVAILABLE, never VALID."""
    entry = case("A-07")
    claim_id, receipt = run_case(shield, direct_vm, policy_id, "A-07")
    assert receipt["verdict"] == "INCONCLUSIVE"
    warp(direct_vm, "2026-09-10T12:05:00Z")
    kinds, urls, hashes = evidence_lists(entry["claim"])
    friendly = BASE + "evidence/legit/witness_statement.txt"
    shield.retry_claim(claim_id, ["WITNESS_STATEMENT"], [friendly], [hashes[4]])
    view = shield.get_claim(claim_id)
    assert view["evidence"][4]["sha256"] == hashes[4]
    stage(direct_vm, case("L-01"))
    assert shield.resolve_claim(claim_id) == "UNAVAILABLE"
    receipt = shield.get_receipt(claim_id + "-R2")
    assert receipt["rows"][4]["status"] == "HASH_MISMATCH"


def test_cancel_and_resubmit_cannot_launder_a_recorded_finding(shield, direct_vm,
                                                               policy_id):
    """A-07 is INCONCLUSIVE because of a contradicting witness. Cancelling it
    and resubmitting the other five documents without the witness is caught:
    those documents were judged by a round of a claim that is now cancelled,
    so the own-cancelled exemption does not apply."""
    claim_id, receipt = run_case(shield, direct_vm, policy_id, "A-07")
    assert receipt["verdict"] == "INCONCLUSIVE"
    shield.cancel_claim(claim_id)
    entry = case("L-01")
    entry["claim"]["evidence"] = [e for e in entry["claim"]["evidence"]
                                  if e["kind"] != "WITNESS_STATEMENT"]
    resubmitted = submit(shield, policy_id, entry["claim"], "AGAIN")
    direct_vm.clear_mocks()
    mock_documents(direct_vm, entry["claim"])
    answer = panel_answer(case("L-01"))
    answer["criteria"]["C4"]["quotes"][0]["evidence_id"] = "E4"
    mock_panel(direct_vm, answer)
    assert shield.resolve_claim(resubmitted) == "SUSPICIOUS"
    assert "DUPLICATE_EVIDENCE" in present(shield.get_receipt(resubmitted + "-R1"))


def test_missing_evidence_can_be_completed_on_retry(shield, direct_vm, policy_id):
    claim_id, receipt = run_case(shield, direct_vm, policy_id, "A-14")
    assert receipt["verdict"] == "INCONCLUSIVE"
    warp(direct_vm, "2026-09-10T12:05:00Z")
    ownership = {"kind": "OWNERSHIP_RECORD", "file": "registry/ownership_record.txt"}
    kinds, urls, hashes = evidence_lists({"evidence": [ownership]})
    shield.retry_claim(claim_id, kinds, urls, hashes)
    view = shield.get_claim(claim_id)
    assert [e["evidence_id"] for e in view["evidence"]] == ["E1", "E2", "E3",
                                                            "E4", "E5"]
    assert view["evidence"][4]["trusted"] is True
    entry = case("A-14")
    entry["claim"]["evidence"].append(ownership)
    answer = panel_answer(case("L-01"))
    answer["criteria"]["C4"]["quotes"] = [
        {"evidence_id": "E5", "text": "Registered keeper: Amara Okafor"}]
    answer["criteria"]["C4"]["evidence_ids"] = ["E5"]
    direct_vm.clear_mocks()
    mock_documents(direct_vm, entry["claim"])
    mock_panel(direct_vm, answer)
    assert shield.resolve_claim(claim_id) == "VALID"


def test_double_dipping_by_the_same_claimant_is_a_duplicate(shield, direct_vm,
                                                            policy_id):
    run_case(shield, direct_vm, policy_id, "L-01", reference="FIRST")
    _c, receipt = run_case(shield, direct_vm, policy_id, "L-01", reference="AGAIN")
    assert receipt["verdict"] == "SUSPICIOUS"
    assert {"DUPLICATE_EVIDENCE", "DUPLICATE_DOCUMENT"} <= set(present(receipt))
    assert receipt["severity"] == "CRITICAL"


def test_reusing_an_ownership_record_is_not_a_duplicate(shield, direct_vm,
                                                        policy_id):
    run_case(shield, direct_vm, policy_id, "L-01")
    _c, receipt = run_case(shield, direct_vm, policy_id, "L-02")
    assert receipt["verdict"] == "VALID"
    assert finding(receipt, "indicators", "DUPLICATE_EVIDENCE")["state"] == "ABSENT"


def test_relabelling_a_reused_invoice_does_not_escape(shield, direct_vm, policy_id):
    run_case(shield, direct_vm, policy_id, "L-01")
    claim = {
        "claim_description": "Deer strike on 7 September 2026.",
        "incident_date": "2026-09-07", "claimed_amount": 443000,
        "evidence": [
            {"kind": "INCIDENT_REPORT", "file": "evidence/unusual/incident_report.txt"},
            {"kind": "INVOICE", "file": "evidence/unusual/repair_invoice.json"},
            {"kind": "OWNERSHIP_RECORD", "file": "evidence/legit/repair_invoice.json"},
        ],
    }
    claim_id = submit(shield, policy_id, claim, "RELABEL")
    direct_vm.clear_mocks()
    mock_documents(direct_vm, claim)
    mock_panel(direct_vm, panel_answer(case("L-02")))
    assert shield.resolve_claim(claim_id) == "SUSPICIOUS"
    receipt = shield.get_receipt(claim_id + "-R1")
    dup = finding(receipt, "indicators", "DUPLICATE_EVIDENCE")
    assert dup["state"] == "PRESENT" and dup["evidence_ids"] == ["E3"]


# -- the on-chain adversarial-test engine -------------------------------------------

def attack_payload(entry: dict, base: str = BASE) -> str:
    kinds, urls, hashes = evidence_lists(entry["claim"], base)
    return json.dumps({
        "claim_description": entry["claim"]["claim_description"],
        "incident_date": entry["claim"]["incident_date"],
        "claimed_amount": entry["claim"]["claimed_amount"],
        "evidence": [{"kind": kinds[i], "url": urls[i], "sha256": hashes[i]}
                     for i in range(len(kinds))],
    })


def register(shield, policy_id: str, case_id: str, version: int = 1) -> str:
    entry = case(case_id)
    indicator = entry["expected_indicators"][0] if entry["expected_indicators"] else ""
    return shield.register_adversarial_test(
        policy_id, version, entry["test_type"], entry["title"],
        attack_payload(entry), entry["expected_property"], indicator)


@pytest.mark.parametrize("case_id", STANDALONE)
def test_every_standalone_case_passes_as_an_onchain_test(shield, direct_vm,
                                                         policy_id, case_id):
    entry = case(case_id)
    test_id = register(shield, policy_id, case_id)
    stage(direct_vm, entry)
    assert shield.run_adversarial_test(test_id) == entry["expected_outcome"]
    view = shield.get_adversarial_test(test_id)
    assert view["status"] == "RAN" and view["passed"] is True
    assert view["observed_verdict"] == entry["expected_outcome"]
    receipt = shield.get_receipt(view["receipt_id"])
    assert receipt["subject_kind"] == "TEST"
    for e in view["attack_payload"]["evidence"]:
        assert shield.evidence_owner(e["sha256"]) == ""   # tests never register


def test_a_failed_safety_property_is_recorded_as_failed(shield, direct_vm, policy_id):
    entry = case("L-01")
    test_id = shield.register_adversarial_test(
        policy_id, 1, "LEGITIMATE_BASELINE", "baseline expected (wrongly) to fail",
        attack_payload(entry), "NOT_VALID", "")
    stage(direct_vm, entry)
    assert shield.run_adversarial_test(test_id) == "VALID"
    view = shield.get_adversarial_test(test_id)
    assert view["passed"] is False and view["observed_verdict"] == "VALID"


def test_expected_indicator_must_also_be_present(shield, direct_vm, policy_id):
    entry = case("A-01")
    test_id = shield.register_adversarial_test(
        policy_id, 1, "FABRICATED_INVOICE", "wrong indicator",
        attack_payload(entry), "VERDICT_SUSPICIOUS", "ARITHMETIC_MISMATCH")
    stage(direct_vm, entry)
    shield.run_adversarial_test(test_id)
    view = shield.get_adversarial_test(test_id)
    assert view["observed_verdict"] == "SUSPICIOUS"
    assert view["observed_indicators"] == ["DATE_CONFLICT"]
    assert view["passed"] is False


@pytest.mark.parametrize("order", ["forward", "reverse"])
def test_adversarial_test_order_does_not_change_results(shield, direct_vm,
                                                        policy_id, order):
    ids = ["A-01", "A-07", "A-09", "A-11", "A-13", "A-15"]
    tests = {cid: register(shield, policy_id, cid) for cid in ids}
    run_order = ids if order == "forward" else list(reversed(ids))
    for cid in run_order:
        stage(direct_vm, case(cid))
        shield.run_adversarial_test(tests[cid])
    for cid in ids:
        view = shield.get_adversarial_test(tests[cid])
        assert view["observed_verdict"] == case(cid)["expected_outcome"]
        assert view["passed"] is True


def test_a_test_is_evaluated_against_the_live_registry(shield, direct_vm,
                                                       policy_id):
    """Tests do not write the registry but do read it: an attack replaying a
    real claim's documents is evaluated as the duplicate it would be."""
    run_case(shield, direct_vm, policy_id, "L-01")
    test_id = shield.register_adversarial_test(
        policy_id, 1, "DUPLICATE_CLAIM", "replay a resolved claim",
        attack_payload(case("L-01")), "VERDICT_SUSPICIOUS", "DUPLICATE_EVIDENCE")
    stage(direct_vm, case("L-01"))
    assert shield.run_adversarial_test(test_id) == "SUSPICIOUS"
    assert shield.get_adversarial_test(test_id)["passed"] is True


def test_tests_run_once(shield, direct_vm, policy_id):
    test_id = register(shield, policy_id, "A-19")
    shield.run_adversarial_test(test_id)
    with direct_vm.expect_revert("test has already run"):
        shield.run_adversarial_test(test_id)


def test_test_registration_rules(shield, direct_vm, direct_bob, policy_id):
    payload = attack_payload(case("A-01"))
    with direct_vm.prank(direct_bob):
        with direct_vm.expect_revert("only the policy owner can register a test"):
            shield.register_adversarial_test(policy_id, 1, "OTHER", "x", payload,
                                             "NOT_VALID", "")
    with direct_vm.expect_revert("unknown policy version"):
        shield.register_adversarial_test(policy_id, 2, "OTHER", "x", payload,
                                         "NOT_VALID", "")
    with direct_vm.expect_revert("test_type must be one of"):
        shield.register_adversarial_test(policy_id, 1, "HEIST", "x", payload,
                                         "NOT_VALID", "")
    with direct_vm.expect_revert("expected_property must be one of"):
        shield.register_adversarial_test(policy_id, 1, "OTHER", "x", payload,
                                         "VERDICT_MAYBE", "")
    with direct_vm.expect_revert("expected_indicator must be empty"):
        shield.register_adversarial_test(policy_id, 1, "OTHER", "x", payload,
                                         "NOT_VALID", "VIBES_OFF")
    with direct_vm.expect_revert("attack_description is required"):
        shield.register_adversarial_test(policy_id, 1, "OTHER", "", payload,
                                         "NOT_VALID", "")
    bad = json.loads(payload)
    bad["evidence"][0]["url"] = "http://evidence.example.org/x.txt"
    with direct_vm.expect_revert("evidence url must use https"):
        shield.register_adversarial_test(policy_id, 1, "OTHER", "x",
                                         json.dumps(bad), "NOT_VALID", "")
    bad = json.loads(payload)
    bad["verdict"] = "VALID"
    with direct_vm.expect_revert("attack_payload keys must be exactly"):
        shield.register_adversarial_test(policy_id, 1, "OTHER", "x",
                                         json.dumps(bad), "NOT_VALID", "")
    bad = json.loads(payload)
    bad["claimed_amount"] = 412000.0
    with direct_vm.expect_revert("claimed_amount must be an integer"):
        shield.register_adversarial_test(policy_id, 1, "OTHER", "x",
                                         json.dumps(bad), "NOT_VALID", "")


def test_tests_per_version_are_bounded(shield, direct_vm, policy_id):
    for _ in range(24):
        register(shield, policy_id, "A-19")
    with direct_vm.expect_revert("policy version has reached 24 tests"):
        register(shield, policy_id, "A-19")


def test_replay_evaluates_a_rule_change_against_old_attacks(shield, direct_vm,
                                                            policy_id):
    """v2 widens the estimate tolerance to 60%: the overrun attack that v1
    caught (A-04) is replayed onto v2 and no longer holds - which is exactly
    what an insurer needs to see before adopting the change."""
    from tests.direct.support import policy_json
    v1_test = register(shield, policy_id, "A-04")
    stage(direct_vm, case("A-04"))
    shield.run_adversarial_test(v1_test)
    assert shield.get_adversarial_test(v1_test)["passed"] is True
    shield.publish_policy_version(policy_id, policy_json(estimate_tolerance_bps=6000))
    v2_test = shield.replay_adversarial_test(v1_test, 2)
    view = shield.get_adversarial_test(v2_test)
    assert view["policy_version"] == 2 and view["source_test_id"] == v1_test
    assert view["status"] == "REGISTERED"
    stage(direct_vm, case("A-04"))
    mock_panel(direct_vm, panel_answer(case("L-01")))
    shield.run_adversarial_test(v2_test)
    view = shield.get_adversarial_test(v2_test)
    assert view["passed"] is False
    assert "ESTIMATE_EXCEEDED" not in view["observed_indicators"]
    assert shield.list_adversarial_tests(policy_id, 2, 0, 10)["items"] == [v2_test]


def test_replay_rules(shield, direct_vm, direct_bob, policy_id):
    test_id = register(shield, policy_id, "A-19")
    with direct_vm.expect_revert("unknown test_id"):
        shield.replay_adversarial_test("AT-000404", 1)
    with direct_vm.expect_revert("unknown target version"):
        shield.replay_adversarial_test(test_id, 3)
    with direct_vm.prank(direct_bob):
        with direct_vm.expect_revert("only the policy owner can replay a test"):
            shield.replay_adversarial_test(test_id, 1)
    shield.revoke_policy_version(policy_id, 1)
    with direct_vm.expect_revert("target version is revoked"):
        shield.replay_adversarial_test(test_id, 1)
    with direct_vm.expect_revert("policy version is revoked"):
        register(shield, policy_id, "A-19")
