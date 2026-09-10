"""Shared scenario data and mock helpers for the Direct Mode suite.

The suite runs the real contract inside the official genlayer-test direct
runner (SDK resolved from the contract's own pinned runner hash). Only the
two external boundaries are mocked, and narrowly:

- web fetches, per exact URL, serving the exact bytes of a file under
  fixtures/ (an unmocked URL is unreachable, so the contract records the
  document UNAVAILABLE - a hidden fetch surfaces as an unexpected row);
- the one panel prompt, matched on its header, answered with a JSON object.

Nothing in the contract's resolution method is patched: every verdict in
this suite is produced by the contract's own code from those two inputs.
"""

import copy
import hashlib
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTRACT = "contracts/insureshield.py"
FIXTURES = ROOT / "fixtures"

BASE = "https://evidence.example.org/insureshield/"
TRUSTED_PREFIX = BASE + "registry/"
NOW = "2026-09-10T12:00:00Z"
PANEL_PATTERN = r"(?s)InsureShield claims evidence panel"

SECTIONS = ("criteria", "exclusions", "indicators")


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


LEGITIMATE = load_fixture("legitimate_claims.json")
ADVERSARIAL = load_fixture("adversarial_claims.json")
CASES = {c["case_id"]: c for c in LEGITIMATE["cases"] + ADVERSARIAL["cases"]}


def file_bytes(rel: str) -> bytes:
    return (FIXTURES / rel).read_bytes()


def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def policy_definition(prefix: str = TRUSTED_PREFIX, **overrides) -> dict:
    """The canonical motor policy every scenario is judged under."""
    definition = {
        "policy_type": "AUTO",
        "coverage_description": (
            "Accidental physical damage to the insured private car - a 2021 "
            "Toyota Corolla, registration EF21 KXT, VIN JTDBR32E720123456, "
            "policyholder Amara Okafor - caused by a collision, including "
            "collisions with other vehicles, animals and fixed objects."),
        "currency": "USD",
        "coverage_start": "2026-01-01",
        "coverage_end": "2026-12-31",
        "reporting_window_days": 30,
        "maximum_claim_amount": 800000,
        "minimum_evidence_count": 3,
        "maximum_evidence_count": 6,
        "estimate_tolerance_bps": 1500,
        "retry_cooldown_seconds": 60,
        "receipt_validity_seconds": 2592000,
        "criteria": [
            {"criterion_id": "C1", "kind": "EVIDENCE_EXAMINED",
             "evidence_kind": "INCIDENT_REPORT", "text": "",
             "critical": True, "trusted_only": False},
            {"criterion_id": "C2", "kind": "AMOUNT_DOCUMENTED",
             "evidence_kind": "INVOICE", "text": "",
             "critical": True, "trusted_only": False},
            {"criterion_id": "C3", "kind": "SEMANTIC",
             "evidence_kind": "INCIDENT_REPORT",
             "text": ("The incident report describes a collision involving "
                      "the insured vehicle on the claimed incident date."),
             "critical": True, "trusted_only": False},
            {"criterion_id": "C4", "kind": "SEMANTIC",
             "evidence_kind": "OWNERSHIP_RECORD",
             "text": ("The ownership record identifies the insured vehicle by "
                      "its VIN and names the policyholder, Amara Okafor, as "
                      "the registered keeper."),
             "critical": True, "trusted_only": True},
            {"criterion_id": "C5", "kind": "SEMANTIC",
             "evidence_kind": "INVOICE",
             "text": ("The repair invoice itemizes repairs to damage "
                      "consistent with the reported collision."),
             "critical": False, "trusted_only": False},
        ],
        "excluded_conditions": [
            {"exclusion_id": "X1", "evidence_kind": "INCIDENT_REPORT",
             "text": ("The vehicle was being used for paid delivery, "
                      "ride-hailing or other commercial purposes at the time "
                      "of the incident.")},
            {"exclusion_id": "X2", "evidence_kind": "",
             "text": ("The driver was under the influence of alcohol or drugs "
                      "at the time of the incident.")},
        ],
        "trusted_sources": [prefix],
    }
    definition.update(overrides)
    return definition


def policy_json(**overrides) -> str:
    return json.dumps(policy_definition(**overrides))


def case(case_id: str) -> dict:
    return copy.deepcopy(CASES[case_id])


def evidence_lists(claim: dict, base: str = BASE) -> tuple:
    kinds, urls, hashes = [], [], []
    for e in claim["evidence"]:
        kinds.append(e["kind"])
        urls.append(base + e["file"])
        hashes.append(sha256_hex(file_bytes(e.get("sha256_of", e["file"]))))
    return kinds, urls, hashes


def mock_url(direct_vm, url: str, body: bytes, status: int = 200):
    direct_vm.mock_web("^" + re.escape(url) + "$", {
        "method": "GET",
        "response": {"status": status, "headers": {}, "body": body},
    })


def mock_documents(direct_vm, claim: dict, base: str = BASE, skip=(),
                   bodies=None):
    """Serve every evidence file that exists under fixtures/ at its URL.
    Files listed in `skip`, and files that do not exist, stay unreachable.
    `bodies` maps a file to replacement bytes."""
    bodies = bodies or {}
    for e in claim["evidence"]:
        rel = e["file"]
        if rel in skip:
            continue
        if rel in bodies:
            mock_url(direct_vm, base + rel, bodies[rel])
            continue
        path = FIXTURES / rel
        if path.exists():
            mock_url(direct_vm, base + rel, path.read_bytes())


def panel_answer(entry: dict):
    """The honest panel answer recorded for a case, or None when the case
    must be decided without the panel."""
    spec = entry["panel"]
    if spec is None:
        return None
    if spec.get("base"):
        answer = copy.deepcopy(LEGITIMATE["panel_bases"][spec["base"]])
    else:
        answer = {s: {} for s in SECTIONS}
    for section in SECTIONS:
        answer[section].update(copy.deepcopy(spec.get(section, {})))
    return answer


def mock_panel(direct_vm, answer):
    payload = answer if isinstance(answer, str) else json.dumps(answer)
    direct_vm.mock_llm(PANEL_PATTERN, payload)


def create_policy(contract, **overrides) -> str:
    return contract.create_policy(policy_json(**overrides))


def submit(contract, policy_id: str, claim: dict, reference: str = "REF-1",
           base: str = BASE, lists=None) -> str:
    kinds, urls, hashes = lists if lists is not None else evidence_lists(claim, base)
    return contract.submit_claim(
        policy_id, reference, claim["claim_description"],
        claim["incident_date"], claim["claimed_amount"], kinds, urls, hashes)


def stage(direct_vm, entry: dict, base: str = BASE):
    """Register the web and panel mocks a case needs."""
    direct_vm.clear_mocks()
    mock_documents(direct_vm, entry["claim"], base)
    answer = panel_answer(entry)
    if answer is not None:
        mock_panel(direct_vm, answer)


def run_case(contract, direct_vm, policy_id: str, case_id: str,
             reference: str = None) -> tuple:
    """Submit and resolve one fixture case; returns (claim_id, receipt)."""
    entry = case(case_id)
    claim_id = submit(contract, policy_id, entry["claim"],
                      reference or ("REF-" + case_id))
    stage(direct_vm, entry)
    contract.resolve_claim(claim_id)
    view = contract.get_claim(claim_id)
    receipt = contract.get_receipt(view["receipt_ids"][-1])
    return claim_id, receipt


def finding(receipt: dict, section: str, subject_id: str) -> dict:
    for f in receipt[section]:
        if f["id"] == subject_id:
            return f
    raise KeyError(subject_id)


def present(receipt: dict) -> list:
    return [f["id"] for f in receipt["indicators"] if f["state"] == "PRESENT"]


def captured_payload(direct_vm) -> dict:
    """The leader's canonical payload captured from the last round."""
    result, _leader_fn, _validator_fn = direct_vm._captured_validators[-1]
    return json.loads(result)


def warp(direct_vm, timestamp: str):
    """Move the transaction clock. genlayer-test 0.29.2's warp() updates the
    VM's datetime but its message refresh copies only sender/origin into the
    SDK's cached gl.message_raw, so a warp after deploy never reaches
    contract code. Set both; this touches the test clock only."""
    import sys
    direct_vm.warp(timestamp)
    gl = sys.modules.get("genlayer.gl")
    if gl is not None and getattr(gl, "message_raw", None) is not None:
        gl.message_raw["datetime"] = timestamp
