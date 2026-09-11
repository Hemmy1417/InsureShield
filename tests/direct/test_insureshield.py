"""Policies, claims, the claim lifecycle, retries, freshness, consumability
and every public view."""

import hashlib
import json

import pytest

from tests.direct.support import (
    BASE, NOW, TRUSTED_PREFIX, case, create_policy, evidence_lists,
    policy_definition, policy_json, run_case, stage, submit, warp,
)


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# -- policies -------------------------------------------------------------------

def test_create_policy_assigns_ids_and_freezes_the_definition(shield):
    first = create_policy(shield)
    second = create_policy(shield)
    assert (first, second) == ("POL-000001", "POL-000002")
    view = shield.get_policy(first, 0)
    assert view["found"] is True
    assert view["version"] == 1 and view["latest_version"] == 1
    assert view["status"] == "ACTIVE"
    assert view["definition"] == policy_definition()
    assert view["claim_count"] == 0 and view["test_count"] == 0


def test_definition_hash_covers_the_canonical_definition(shield, policy_id):
    view = shield.get_policy(policy_id, 1)
    expected = hashlib.sha256(canonical({
        "schema": 1, "policy_id": policy_id, "version": 1,
        "owner": view["owner"], "definition": policy_definition(),
    }).encode()).hexdigest()
    assert view["definition_hash"] == expected
    assert shield.definition_hash(policy_id, 1) == expected
    assert shield.definition_hash(policy_id, 2) == ""
    assert shield.definition_hash("POL-999999", 1) == ""


@pytest.mark.parametrize("overrides, message", [
    ({"policy_type": "MARINE"}, "policy_type must be one of"),
    ({"currency": "usd"}, "currency must be three uppercase letters"),
    ({"coverage_start": "2026-13-01"}, "coverage_start and coverage_end"),
    ({"coverage_start": "2027-01-01"}, "coverage_start is after coverage_end"),
    ({"reporting_window_days": 0}, "reporting_window_days must be an integer"),
    ({"reporting_window_days": True}, "reporting_window_days must be an integer"),
    ({"maximum_claim_amount": 800000.0}, "maximum_claim_amount must be an integer"),
    ({"maximum_claim_amount": 10 ** 15 + 1}, "maximum_claim_amount must be an integer"),
    ({"minimum_evidence_count": 5, "maximum_evidence_count": 4},
     "minimum_evidence_count exceeds maximum_evidence_count"),
    ({"maximum_evidence_count": 7}, "maximum_evidence_count must be an integer"),
    ({"estimate_tolerance_bps": 10001}, "estimate_tolerance_bps must be an integer"),
    ({"retry_cooldown_seconds": 59}, "retry_cooldown_seconds must be an integer"),
    ({"receipt_validity_seconds": 3599}, "receipt_validity_seconds must be an integer"),
    ({"criteria": []}, "criteria must hold 1 to 8 entries"),
    ({"excluded_conditions": [{"exclusion_id": "X1", "evidence_kind": "",
                               "text": "a"}] * 5},
     "excluded_conditions must hold at most 4"),
    ({"trusted_sources": ["http://registry.example.org/"]},
     "trusted source: evidence url must use https"),
    ({"trusted_sources": ["https://registry.example.org/file.txt"]},
     "trusted source must be a path prefix ending in /"),
    ({"trusted_sources": ["https://registry.example.org/a/?q=1/"]},
     "trusted source must be a path prefix"),
    ({"trusted_sources": [TRUSTED_PREFIX, TRUSTED_PREFIX]},
     "trusted_sources contains a duplicate"),
])
def test_definition_validation_refuses(shield, direct_vm, overrides, message):
    with direct_vm.expect_revert(message):
        shield.create_policy(policy_json(**overrides))


def criterion(**over):
    base = {"criterion_id": "C9", "kind": "SEMANTIC", "evidence_kind": "",
            "text": "The documents describe a collision.", "critical": True,
            "trusted_only": False}
    base.update(over)
    return base


@pytest.mark.parametrize("bad, message", [
    (criterion(criterion_id="c9"), "criterion_id must be a unique id"),
    (criterion(criterion_id="C1"), "criterion_id must be a unique id"),
    (criterion(kind="VIBES"), "criterion kind must be one of"),
    (criterion(critical=1), "critical and trusted_only must be booleans"),
    (criterion(trusted_only="yes"), "critical and trusted_only must be booleans"),
    (criterion(kind="EVIDENCE_EXAMINED", evidence_kind=""),
     "EVIDENCE_EXAMINED needs an evidence_kind"),
    (criterion(kind="AMOUNT_DOCUMENTED", evidence_kind="PHOTO_LOG"),
     "AMOUNT_DOCUMENTED needs INVOICE or REPAIR_ESTIMATE"),
    (criterion(evidence_kind="SELFIE"), "SEMANTIC evidence_kind must be a kind or empty"),
    (criterion(text=""), "criterion text is required"),
    (criterion(text="x" * 301), "criterion text exceeds 300"),
    (criterion(text="line\nbreak"), "criterion text contains control characters"),
    (dict(criterion(), extra=1), "criterion keys must be exactly"),
])
def test_criterion_validation_refuses(shield, direct_vm, bad, message):
    criteria = policy_definition()["criteria"] + [bad]
    with direct_vm.expect_revert(message):
        shield.create_policy(policy_json(criteria=criteria))


def test_trusted_only_needs_a_trusted_source(shield, direct_vm):
    with direct_vm.expect_revert("trusted_only needs at least one trusted source"):
        shield.create_policy(policy_json(trusted_sources=[]))


def test_definition_must_have_exactly_the_documented_keys(shield, direct_vm):
    d = policy_definition()
    d["payout_address"] = "0x0"
    with direct_vm.expect_revert("definition keys must be exactly"):
        shield.create_policy(json.dumps(d))
    d = policy_definition()
    del d["criteria"]
    with direct_vm.expect_revert("definition keys must be exactly"):
        shield.create_policy(json.dumps(d))
    with direct_vm.expect_revert("definition is not valid JSON"):
        shield.create_policy("{not json")


def test_publish_supersedes_and_new_claims_bind_the_new_version(
        shield, direct_vm, policy_id):
    entry = case("L-01")
    old_claim = submit(shield, policy_id, entry["claim"], "OLD")
    v2 = shield.publish_policy_version(
        policy_id, policy_json(reporting_window_days=10))
    assert v2 == 2
    assert shield.get_policy(policy_id, 1)["status"] == "SUPERSEDED"
    assert shield.get_policy(policy_id, 2)["status"] == "ACTIVE"
    assert shield.get_policy(policy_id, 0)["version"] == 2
    new_claim = submit(shield, policy_id, entry["claim"], "NEW")
    old_view = shield.get_claim(old_claim)
    new_view = shield.get_claim(new_claim)
    assert old_view["policy_version"] == 1 and new_view["policy_version"] == 2
    assert old_view["definition_hash"] == shield.definition_hash(policy_id, 1)
    assert new_view["definition_hash"] == shield.definition_hash(policy_id, 2)
    assert old_view["definition_hash"] != new_view["definition_hash"]


def test_old_claims_resolve_under_their_bound_version(shield, direct_vm, policy_id):
    """A policy cannot be changed retroactively: a claim submitted under v1
    is judged under v1 even after v2 tightens the reporting window so far
    that the same claim would be late."""
    entry = case("L-01")
    claim_id = submit(shield, policy_id, entry["claim"], "OLD")
    shield.publish_policy_version(policy_id, policy_json(reporting_window_days=1))
    stage(direct_vm, entry)
    assert shield.resolve_claim(claim_id) == "VALID"
    receipt = shield.get_receipt(claim_id + "-R1")
    assert receipt["policy_version"] == 1
    assert receipt["definition_hash"] == shield.definition_hash(policy_id, 1)


def test_only_the_owner_publishes_or_revokes(shield, direct_vm, direct_bob,
                                             policy_id):
    with direct_vm.prank(direct_bob):
        with direct_vm.expect_revert("only the policy owner can publish"):
            shield.publish_policy_version(policy_id, policy_json())
        with direct_vm.expect_revert("only the policy owner can revoke"):
            shield.revoke_policy_version(policy_id, 1)


def test_version_cap(shield, direct_vm, policy_id):
    for _ in range(7):
        shield.publish_policy_version(policy_id, policy_json())
    with direct_vm.expect_revert("policy has reached 8 versions"):
        shield.publish_policy_version(policy_id, policy_json())


def test_revoked_version_accepts_no_claims_until_a_new_version(
        shield, direct_vm, policy_id):
    shield.revoke_policy_version(policy_id, 1)
    assert shield.get_policy(policy_id, 1)["status"] == "REVOKED"
    with direct_vm.expect_revert("policy has no active version"):
        submit(shield, policy_id, case("L-01")["claim"])
    with direct_vm.expect_revert("policy version is already revoked"):
        shield.revoke_policy_version(policy_id, 1)
    assert shield.publish_policy_version(policy_id, policy_json()) == 2
    submit(shield, policy_id, case("L-01")["claim"])


def test_unknown_policy_references(shield, direct_vm):
    with direct_vm.expect_revert("unknown policy_id"):
        submit(shield, "POL-000404", case("L-01")["claim"])
    with direct_vm.expect_revert("unknown policy_id"):
        shield.publish_policy_version("POL-000404", policy_json())
    with direct_vm.expect_revert("unknown policy version"):
        shield.revoke_policy_version("POL-000404", 1)
    assert shield.get_policy("POL-000404", 0) == {"found": False,
                                                  "policy_id": "POL-000404"}


# -- claim submission -------------------------------------------------------------

def test_submit_records_evidence_commitment_and_registry(shield, policy_id):
    entry = case("L-01")
    kinds, urls, hashes = evidence_lists(entry["claim"])
    claim_id = submit(shield, policy_id, entry["claim"])
    assert claim_id == "CLM-000001"
    view = shield.get_claim(claim_id)
    assert view["status"] == "PENDING" and view["verdict"] == ""
    assert [e["evidence_id"] for e in view["evidence"]] == \
        ["E1", "E2", "E3", "E4", "E5", "E6"]
    assert [e["kind"] for e in view["evidence"]] == kinds
    assert [e["url"] for e in view["evidence"]] == urls
    assert [e["sha256"] for e in view["evidence"]] == hashes
    assert [e["trusted"] for e in view["evidence"]] == \
        [False, False, False, True, False, False]
    expected = hashlib.sha256(canonical([
        {"evidence_id": e["evidence_id"], "kind": e["kind"], "url": e["url"],
         "sha256": e["sha256"]} for e in view["evidence"]]).encode()).hexdigest()
    assert view["evidence_commitment"] == expected
    for digest in hashes:
        assert shield.evidence_owner(digest) == claim_id
    assert shield.evidence_owner("0" * 64) == ""
    assert shield.list_claims(policy_id, 1, 0, 10) == {"total": 1,
                                                      "items": [claim_id]}


def claim_with(**over):
    claim = case("L-01")["claim"]
    claim.update(over)
    return claim


@pytest.mark.parametrize("over, message", [
    ({"claim_description": ""}, "claim_description is required"),
    ({"claim_description": "x" * 801}, "claim_description exceeds 800"),
    ({"claim_description": "tab\there"}, "claim_description contains control"),
    ({"incident_date": "2026-02-30"}, "incident_date must be YYYY-MM-DD"),
    ({"incident_date": "2026-09-11"}, "incident_date is in the future"),
    ({"claimed_amount": 0}, "claimed_amount must be an integer"),
    ({"claimed_amount": 10 ** 15 + 1}, "claimed_amount must be an integer"),
])
def test_claim_field_validation(shield, direct_vm, policy_id, over, message):
    with direct_vm.expect_revert(message):
        submit(shield, policy_id, claim_with(**over))


def test_claim_reference_rules(shield, direct_vm, direct_bob, policy_id):
    claim = case("L-01")["claim"]
    with direct_vm.expect_revert("claim_reference must be 1-64"):
        submit(shield, policy_id, claim, "has space")
    submit(shield, policy_id, claim, "REF-A")
    with direct_vm.expect_revert("claim_reference already used by this claimant"):
        submit(shield, policy_id, claim, "REF-A")
    with direct_vm.prank(direct_bob):
        submit(shield, policy_id, claim, "REF-A")


def lists_for(claim):
    return [list(x) for x in evidence_lists(claim)]


def test_evidence_count_bounds(shield, direct_vm, policy_id):
    claim = case("L-01")["claim"]
    kinds, urls, hashes = lists_for(claim)
    with direct_vm.expect_revert("evidence is below the policy minimum of 3"):
        submit(shield, policy_id, claim, lists=(kinds[:2], urls[:2], hashes[:2]))
    extra = (kinds + ["PHOTO_LOG"], urls + [BASE + "x/extra.txt"],
             hashes + ["a" * 64])
    with direct_vm.expect_revert("evidence exceeds the policy maximum of 6"):
        submit(shield, policy_id, claim, lists=extra)
    with direct_vm.expect_revert("must have equal length"):
        submit(shield, policy_id, claim, lists=(kinds, urls[:5], hashes))


def test_evidence_entry_validation(shield, direct_vm, policy_id):
    claim = case("L-01")["claim"]
    kinds, urls, hashes = lists_for(claim)
    bad_kind = (["SELFIE"] + kinds[1:], urls, hashes)
    with direct_vm.expect_revert("evidence kind must be one of"):
        submit(shield, policy_id, claim, lists=bad_kind)
    bad_hash = (kinds, urls, ["A" * 64] + hashes[1:])
    with direct_vm.expect_revert("evidence sha256 must be 64 lowercase hex"):
        submit(shield, policy_id, claim, lists=bad_hash)
    same_doc = (kinds, urls, [hashes[0], hashes[0]] + hashes[2:])
    with direct_vm.expect_revert("evidence contains the same document twice"):
        submit(shield, policy_id, claim, lists=same_doc)
    same_url = (kinds, [urls[0], urls[0]] + urls[2:], hashes)
    with direct_vm.expect_revert("evidence contains the same location twice"):
        submit(shield, policy_id, claim, lists=same_url)
    cased = (kinds, [urls[0], urls[0].replace("evidence.example.org",
                                              "EVIDENCE.example.org")]
             + urls[2:], hashes)
    with direct_vm.expect_revert("evidence contains the same location twice"):
        submit(shield, policy_id, claim, lists=cased)


def test_trusted_flag_uses_the_canonical_url(shield, policy_id):
    claim = case("L-01")["claim"]
    kinds, urls, hashes = lists_for(claim)
    urls[3] = urls[3].replace("evidence.example.org", "Evidence.Example.org:443")
    claim_id = submit(shield, policy_id, claim, lists=(kinds, urls, hashes))
    item = shield.get_claim(claim_id)["evidence"][3]
    assert item["url"] == BASE + "registry/ownership_record.txt"
    assert item["trusted"] is True


def test_a_lookalike_prefix_is_not_trusted(shield, policy_id):
    claim = case("L-01")["claim"]
    kinds, urls, hashes = lists_for(claim)
    urls[3] = BASE + "registry-mirror/ownership_record.txt"
    claim_id = submit(shield, policy_id, claim, lists=(kinds, urls, hashes))
    assert shield.get_claim(claim_id)["evidence"][3]["trusted"] is False


# -- resolution and lifecycle -----------------------------------------------------

def test_valid_claim_lifecycle_and_receipt(shield, direct_vm, policy_id):
    claim_id, receipt = run_case(shield, direct_vm, policy_id, "L-01")
    view = shield.get_claim(claim_id)
    assert view["status"] == "RESOLVED" and view["verdict"] == "VALID"
    assert view["severity"] == "NONE" and view["confidence_band"] == "HIGH"
    assert view["failure_class"] == "NONE"
    assert view["resolved_at"] == NOW
    assert view["receipt_ids"] == [claim_id + "-R1"]
    assert receipt["found"] is True
    assert receipt["subject_kind"] == "CLAIM" and receipt["round"] == 1
    assert receipt["evidence_commitment"] == view["evidence_commitment"]
    assert receipt["source_reachability"] == "REACHABLE"
    assert receipt["panel_state"] == "ASSESSED"
    assert receipt["deterministic_only"] is False
    assert [r["status"] for r in receipt["rows"]] == ["EXAMINED"] * 6
    assert [f["evidence_id"] for f in receipt["facts"]] == ["E2", "E3"]
    assert receipt["facts"][1]["total"] == 438500
    assert receipt["reason_codes"] == ["ALL_CRITERIA_SATISFIED"]
    assert shield.latest_verdict(claim_id) == "VALID"


def test_receipt_digests_cover_the_stored_record(shield, direct_vm, policy_id):
    claim_id, receipt = run_case(shield, direct_vm, policy_id, "L-01")
    stored = dict(receipt)
    del stored["found"]
    digest = stored.pop("record_digest")
    assert hashlib.sha256(canonical(stored).encode()).hexdigest() == digest
    assert receipt["evidence_digest"] == hashlib.sha256(canonical({
        "evidence_commitment": receipt["evidence_commitment"],
        "rows": receipt["rows"], "facts": receipt["facts"],
    }).encode()).hexdigest()


def test_resolution_is_permissionless(shield, direct_vm, direct_bob, policy_id):
    entry = case("L-01")
    claim_id = submit(shield, policy_id, entry["claim"])
    stage(direct_vm, entry)
    with direct_vm.prank(direct_bob):
        assert shield.resolve_claim(claim_id) == "VALID"


def test_a_terminal_claim_cannot_be_resolved_twice(shield, direct_vm, policy_id):
    claim_id, _receipt = run_case(shield, direct_vm, policy_id, "L-01")
    with direct_vm.expect_revert("claim is not pending resolution"):
        shield.resolve_claim(claim_id)
    with direct_vm.expect_revert("claim is not retryable"):
        shield.retry_claim(claim_id, [], [], [])
    with direct_vm.expect_revert("claim is already terminal"):
        shield.cancel_claim(claim_id)
    assert shield.get_claim(claim_id)["receipt_ids"] == [claim_id + "-R1"]


def test_unknown_claim_references(shield, direct_vm):
    with direct_vm.expect_revert("unknown claim_id"):
        shield.resolve_claim("CLM-000404")
    with direct_vm.expect_revert("unknown claim_id"):
        shield.retry_claim("CLM-000404", [], [], [])
    with direct_vm.expect_revert("unknown claim_id"):
        shield.cancel_claim("CLM-000404")
    assert shield.get_claim("CLM-000404")["found"] is False
    assert shield.get_receipt("CLM-000404-R1")["found"] is False
    assert shield.latest_verdict("CLM-000404") == ""
    assert shield.freshness("CLM-000404", NOW) == "UNKNOWN"
    assert shield.is_fresh("CLM-000404", NOW) is False
    assert shield.is_consumable("CLM-000404", NOW) is False
    assert shield.claim_outcome("CLM-000404", NOW)["found"] is False
    assert shield.get_adversarial_test("AT-000404")["found"] is False


def unavailable_claim(shield, direct_vm, policy_id):
    return run_case(shield, direct_vm, policy_id, "A-15")[0]


def test_unavailable_leaves_the_claim_retryable_with_a_cooldown(
        shield, direct_vm, policy_id):
    claim_id = unavailable_claim(shield, direct_vm, policy_id)
    view = shield.get_claim(claim_id)
    assert view["status"] == "RETRYABLE" and view["verdict"] == "UNAVAILABLE"
    assert view["failure_class"] == "EVIDENCE_UNREACHABLE"
    assert view["resolved_at"] == ""
    with direct_vm.expect_revert("retry cooldown has not elapsed"):
        shield.retry_claim(claim_id, [], [], [])
    warp(direct_vm, "2026-09-10T12:01:00Z")
    shield.retry_claim(claim_id, [], [], [])
    assert shield.get_claim(claim_id)["status"] == "PENDING"
    assert shield.get_claim(claim_id)["retry_count"] == 1


def test_only_the_claimant_retries_or_cancels(shield, direct_vm, direct_bob,
                                              policy_id):
    claim_id = unavailable_claim(shield, direct_vm, policy_id)
    warp(direct_vm, "2026-09-10T12:05:00Z")
    with direct_vm.prank(direct_bob):
        with direct_vm.expect_revert("only the claimant can retry a claim"):
            shield.retry_claim(claim_id, [], [], [])
        with direct_vm.expect_revert("only the claimant can cancel a claim"):
            shield.cancel_claim(claim_id)


def test_retry_relocates_a_document_and_the_next_round_uses_it(
        shield, direct_vm, policy_id):
    entry = case("A-15")
    claim_id = unavailable_claim(shield, direct_vm, policy_id)
    warp(direct_vm, "2026-09-10T12:05:00Z")
    photo = entry["claim"]["evidence"][5]
    new_url = BASE + "evidence/legit/photo_log.txt"
    digest = evidence_lists(entry["claim"])[2][5]
    shield.retry_claim(claim_id, ["PHOTO_LOG"], [new_url], [digest])
    view = shield.get_claim(claim_id)
    assert len(view["evidence"]) == 6
    assert view["evidence"][5]["evidence_id"] == "E6"
    assert view["evidence"][5]["url"] == new_url
    assert view["evidence"][5]["sha256"] == digest
    healed = case("L-01")
    stage(direct_vm, healed)
    assert shield.resolve_claim(claim_id) == "VALID"
    view = shield.get_claim(claim_id)
    assert view["receipt_ids"] == [claim_id + "-R1", claim_id + "-R2"]
    r1 = shield.get_receipt(claim_id + "-R1")
    r2 = shield.get_receipt(claim_id + "-R2")
    assert r1["evidence"][5]["url"] == BASE + photo["file"]
    assert r2["evidence"][5]["url"] == new_url
    assert r1["evidence_commitment"] != r2["evidence_commitment"]


def test_retry_refuses_changing_a_documents_kind(shield, direct_vm, policy_id):
    entry = case("A-15")
    claim_id = unavailable_claim(shield, direct_vm, policy_id)
    warp(direct_vm, "2026-09-10T12:05:00Z")
    digest = evidence_lists(entry["claim"])[2][5]
    with direct_vm.expect_revert("a relocated document must keep its evidence kind"):
        shield.retry_claim(claim_id, ["WITNESS_STATEMENT"],
                           [BASE + "evidence/legit/photo_log.txt"], [digest])


def test_retry_cannot_exceed_the_evidence_maximum(shield, direct_vm, policy_id):
    claim_id = unavailable_claim(shield, direct_vm, policy_id)
    warp(direct_vm, "2026-09-10T12:05:00Z")
    with direct_vm.expect_revert("evidence exceeds the policy maximum of 6"):
        shield.retry_claim(claim_id, ["PHOTO_LOG"], [BASE + "new/photo.txt"],
                           ["b" * 64])


def test_rounds_are_bounded_and_the_last_one_is_terminal(shield, direct_vm,
                                                         policy_id):
    claim_id = unavailable_claim(shield, direct_vm, policy_id)
    for minute, round_no in (("12:02", 2), ("12:04", 3)):
        warp(direct_vm, "2026-09-10T" + minute + ":00Z")
        shield.retry_claim(claim_id, [], [], [])
        stage(direct_vm, case("A-15"))
        assert shield.resolve_claim(claim_id) == "UNAVAILABLE"
    view = shield.get_claim(claim_id)
    assert view["status"] == "RESOLVED" and view["verdict"] == "UNAVAILABLE"
    assert len(view["receipt_ids"]) == 3
    warp(direct_vm, "2026-09-10T12:30:00Z")
    with direct_vm.expect_revert("claim is not retryable"):
        shield.retry_claim(claim_id, [], [], [])


def test_cancel_is_terminal(shield, direct_vm, policy_id):
    claim_id = submit(shield, policy_id, case("L-01")["claim"])
    shield.cancel_claim(claim_id)
    view = shield.get_claim(claim_id)
    assert view["status"] == "CANCELLED" and view["resolved_at"] == NOW
    with direct_vm.expect_revert("claim is not pending resolution"):
        shield.resolve_claim(claim_id)
    assert shield.freshness(claim_id, NOW) == "UNKNOWN"
    assert shield.is_consumable(claim_id, NOW) is False


# -- freshness and consumability ----------------------------------------------------

def test_freshness_states(shield, direct_vm, policy_id):
    pending = submit(shield, policy_id, case("L-01")["claim"], "P")
    assert shield.freshness(pending, NOW) == "UNKNOWN"
    shield.cancel_claim(pending)
    claim_id, receipt = run_case(shield, direct_vm, policy_id, "L-01")
    assert receipt["verdict"] == "VALID"   # own cancelled claim is no duplicate
    assert shield.freshness(claim_id, NOW) == "RELIABLE"
    assert shield.is_fresh(claim_id, "2026-10-10T12:00:00Z") is True
    assert shield.freshness(claim_id, "2026-10-10T12:00:01Z") == "STALE"
    assert shield.freshness(claim_id, "2026-09-10T11:59:59Z") == "UNKNOWN"
    assert shield.freshness(claim_id, "yesterday") == "UNKNOWN"
    assert shield.freshness(claim_id, "") == "UNKNOWN"


def test_unavailable_evidence_is_blocked_not_fresh(shield, direct_vm, policy_id):
    blocked = run_case(shield, direct_vm, policy_id, "A-15")[0]
    assert shield.freshness(blocked, NOW) == "BLOCKED"
    assert shield.is_fresh(blocked, NOW) is False


def test_is_consumable_for_a_fresh_valid_resolution(shield, direct_vm,
                                                    policy_id):
    valid, _r = run_case(shield, direct_vm, policy_id, "L-01")
    assert shield.is_consumable(valid, NOW) is True
    assert shield.is_consumable(valid, "2026-11-01T00:00:00Z") is False
    outcome = shield.claim_outcome(valid, NOW)
    assert outcome == {
        "found": True, "claim_id": valid, "status": "RESOLVED",
        "verdict": "VALID", "severity": "NONE", "failure_class": "NONE",
        "confidence_band": "HIGH", "freshness": "RELIABLE", "consumable": True,
        "duplicate_of": "",
        "latest_receipt_id": valid + "-R1", "policy_id": policy_id,
        "policy_version": 1, "definition_hash": shield.definition_hash(policy_id, 1),
    }


@pytest.mark.parametrize("case_id, verdict", [
    ("A-01", "SUSPICIOUS"), ("A-10", "SUSPICIOUS"), ("A-07", "INCONCLUSIVE"),
    ("A-14", "INCONCLUSIVE"), ("A-15", "UNAVAILABLE"), ("A-19", "REJECTED"),
])
def test_no_other_verdict_is_consumable(shield, direct_vm, policy_id, case_id,
                                        verdict):
    claim_id, receipt = run_case(shield, direct_vm, policy_id, case_id)
    assert receipt["verdict"] == verdict
    assert shield.is_consumable(claim_id, NOW) is False
    assert shield.claim_outcome(claim_id, NOW)["consumable"] is False


def test_revoking_a_version_makes_its_claims_stale_and_unconsumable(
        shield, direct_vm, policy_id):
    claim_id, _r = run_case(shield, direct_vm, policy_id, "L-01")
    shield.revoke_policy_version(policy_id, 1)
    assert shield.freshness(claim_id, NOW) == "STALE"
    assert shield.is_consumable(claim_id, NOW) is False
    assert shield.latest_verdict(claim_id) == "VALID"


def test_superseding_a_version_keeps_its_claims_consumable(
        shield, direct_vm, policy_id):
    claim_id, _r = run_case(shield, direct_vm, policy_id, "L-01")
    shield.publish_policy_version(policy_id, policy_json())
    assert shield.is_consumable(claim_id, NOW) is True


# -- views ------------------------------------------------------------------------------

def test_config_and_stats(shield, direct_vm, policy_id):
    config = shield.get_config()
    assert config["contract_version"] == "0.1.0"
    assert config["bounds"]["max_evidence"] == 6
    assert config["bounds"]["max_rounds"] == 3
    assert "PANEL" not in config["indicators"]["code"]
    assert config["verdicts"] == ["VALID", "SUSPICIOUS", "INCONCLUSIVE",
                                  "UNAVAILABLE", "REJECTED"]
    run_case(shield, direct_vm, policy_id, "L-01")
    assert shield.get_stats() == {"policies": 1, "claims": 1, "tests": 0,
                                  "receipts": 1}


def test_list_views_are_bounded_pages(shield, direct_vm, policy_id):
    claim = case("L-01")["claim"]
    ids = [submit(shield, policy_id, claim, "R" + str(i)) for i in range(4)]
    assert shield.list_claims(policy_id, 1, 1, 2) == {"total": 4,
                                                     "items": ids[1:3]}
    assert shield.list_claims(policy_id, 1, 3, 50) == {"total": 4,
                                                      "items": ids[3:]}
    assert shield.list_claims(policy_id, 1, 9, 5)["items"] == []
    assert shield.list_claims(policy_id, 1, -1, 5)["items"] == []
    assert shield.list_claims(policy_id, 1, 0, 0)["items"] == []
    assert shield.list_claims(policy_id, 1, 0, 1000)["items"] == ids
    assert shield.list_claims(policy_id, 2, 0, 5) == {"total": 0, "items": []}
    assert shield.list_adversarial_tests(policy_id, 1, 0, 5) == {"total": 0,
                                                                "items": []}


@pytest.mark.parametrize("window", [{"coverage_end": "2026-09-01"},
                                    {"coverage_start": "2026-09-06"}])
def test_incident_outside_the_coverage_period_is_rejected(shield, direct_vm, window):
    """The incident (2026-09-05) falls after the cover ends, or before it
    starts: both boundaries are enforced."""
    policy_id = create_policy(shield, **window)
    claim_id = submit(shield, policy_id, case("L-01")["claim"])
    direct_vm.clear_mocks()
    assert shield.resolve_claim(claim_id) == "REJECTED"
    receipt = shield.get_receipt(claim_id + "-R1")
    assert receipt["reason_codes"] == ["ADMISSION:INCIDENT_OUTSIDE_COVERAGE"]
    assert receipt["deterministic_only"] is True


@pytest.mark.parametrize("incident, late", [("2026-08-11", False),
                                            ("2026-08-10", True)])
def test_reporting_window_boundary(shield, direct_vm, policy_id, incident, late):
    """Submitted 2026-09-10 under a 30-day window: 30 days after the
    incident is on time, 31 is late."""
    entry = case("L-03")
    entry["claim"]["incident_date"] = incident
    claim_id = submit(shield, policy_id, entry["claim"])
    stage(direct_vm, entry)
    shield.resolve_claim(claim_id)
    reasons = shield.get_receipt(claim_id + "-R1")["reason_codes"]
    assert ("ADMISSION:LATE_NOTICE" in reasons) is late
