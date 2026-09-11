"""Integration against the recorded StudioNet deployment (real network).

Attaches to the canonical deployment in deploy/deployment.json - it does not
deploy - and checks what only the network can show:

  1. the deployed source is byte-identical to contracts/insureshield.py;
  2. the deployed schema exposes exactly the contract's public methods;
  3. the deployed configuration matches the repository's constants;
  4. a deterministic write path end to end through real consensus: a policy,
     then a claim reported outside the reporting window (REJECTED at
     admission, no fetch, no model);
  5. a real round with no model: the fabricated-invoice attack registered as
     an on-chain adversarial test, whose evidence is fetched from
     commit-pinned GitHub raw URLs and hash-verified by every node, decided
     SUSPICIOUS by code.

Writes use a fresh ephemeral account (StudioNet is gasless). Model-decided
outcomes are covered by scripts/live_scenarios.py, not here, so this suite
never depends on a model's reading.

  python -m pytest tests/integration -v
"""

import base64
import hashlib
import json
import pathlib
import time
import urllib.request

import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import studionet_transport  # noqa: E402,F401 - retries RPC transport failures
RECORD = ROOT / "deploy" / "deployment.json"
TRANSCRIPT = ROOT / "deploy" / "live_scenarios_transcript.json"
RPC = "https://studio.genlayer.com/api"

PUBLIC_METHODS = {
    "create_policy", "publish_policy_version", "revoke_policy_version",
    "submit_claim", "resolve_claim", "retry_claim", "cancel_claim",
    "register_adversarial_test", "run_adversarial_test", "replay_adversarial_test",
    "get_config", "get_policy", "definition_hash", "get_claim", "get_receipt",
    "latest_verdict", "freshness", "is_fresh", "is_consumable", "claim_outcome",
    "evidence_owner", "get_adversarial_test", "list_claims",
    "list_adversarial_tests", "get_stats",
}

pytestmark = pytest.mark.skipif(not RECORD.exists(),
                                reason="no recorded deployment (deploy/deployment.json)")


def record() -> dict:
    return json.loads(RECORD.read_text(encoding="utf-8"))


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    for attempt in range(5):
        try:
            request = urllib.request.Request(
                RPC, data=body, headers={"Content-Type": "application/json",
                                         "User-Agent": "insureshield-integration"})
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode())
        except Exception:                 # noqa: BLE001 - transport errors vary
            time.sleep(10 * (attempt + 1))
    pytest.skip("StudioNet RPC unreachable")


def test_deployed_source_is_byte_identical():
    result = rpc("gen_getContractCode", [record()["contract_address"]])["result"]
    deployed = result.encode() if result.lstrip().startswith("#") \
        else base64.b64decode(result)
    local = (ROOT / "contracts" / "insureshield.py").read_bytes()
    assert hashlib.sha256(deployed).hexdigest() == hashlib.sha256(local).hexdigest()
    assert record()["source_sha256"] == hashlib.sha256(local).hexdigest()


def test_deployed_schema_exposes_the_public_interface():
    schema = rpc("gen_getContractSchema", [record()["contract_address"]])["result"]
    assert set(schema["methods"].keys()) == PUBLIC_METHODS


@pytest.fixture(scope="module")
def client():
    from genlayer_py import create_account, create_client
    from genlayer_py.chains import studionet
    account = create_account()
    return create_client(chain=studionet, account=account)


def read(client, fn, args):
    return client.read_contract(address=record()["contract_address"],
                                function_name=fn, args=args)


def write(client, fn, args):
    from genlayer_py.types import TransactionStatus
    tx = client.write_contract(address=record()["contract_address"],
                               function_name=fn, args=args,
                               consensus_max_rotations=3)
    receipt = client.wait_for_transaction_receipt(
        transaction_hash=tx, status=TransactionStatus.FINALIZED,
        interval=5000, retries=240)
    leader = receipt["consensus_data"]["leader_receipt"]
    leader = leader[0] if isinstance(leader, list) else leader
    return str(leader["execution_result"])


def test_deployed_configuration(client):
    config = read(client, "get_config", [])
    assert config["contract_version"] == "0.1.0"
    assert config["bounds"]["max_evidence"] == 6
    assert config["verdicts"] == ["VALID", "SUSPICIOUS", "INCONCLUSIVE",
                                  "UNAVAILABLE", "REJECTED"]


def canonical_definition(raw: str) -> str:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "support", ROOT / "tests" / "direct" / "support.py")
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    return json.dumps(support.policy_definition(prefix=raw + "registry/")), support


@pytest.mark.skipif(not TRANSCRIPT.exists(), reason="no pinned evidence base yet")
def test_admission_and_a_code_decided_round(client):
    raw = json.loads(TRANSCRIPT.read_text(encoding="utf-8"))["raw_base"]
    definition, support = canonical_definition(raw)
    assert write(client, "create_policy", [definition]) == "SUCCESS"
    policy_id = "POL-" + str(read(client, "get_stats", [])["policies"]).zfill(6)
    assert read(client, "get_policy", [policy_id, 1])["owner"].lower() == \
        str(client.local_account.address).lower()

    late = support.case("A-19")
    kinds, urls, hashes = support.evidence_lists(late["claim"], raw)
    assert write(client, "submit_claim", [
        policy_id, "IT-LATE-" + str(int(time.time())),
        late["claim"]["claim_description"], late["claim"]["incident_date"],
        late["claim"]["claimed_amount"], kinds, urls, hashes]) == "SUCCESS"
    claim_id = "CLM-" + str(read(client, "get_stats", [])["claims"]).zfill(6)
    assert write(client, "resolve_claim", [claim_id]) == "SUCCESS"
    receipt = read(client, "get_receipt", [claim_id + "-R1"])
    assert receipt["verdict"] == "REJECTED"
    assert receipt["reason_codes"] == ["ADMISSION:LATE_NOTICE"]
    assert receipt["deterministic_only"] is True

    attack = support.case("A-01")
    kinds, urls, hashes = support.evidence_lists(attack["claim"], raw)
    payload = json.dumps({
        "claim_description": attack["claim"]["claim_description"],
        "incident_date": attack["claim"]["incident_date"],
        "claimed_amount": attack["claim"]["claimed_amount"],
        "evidence": [{"kind": kinds[i], "url": urls[i], "sha256": hashes[i]}
                     for i in range(len(kinds))]})
    assert write(client, "register_adversarial_test", [
        policy_id, 1, "FABRICATED_INVOICE", attack["title"], payload,
        "VERDICT_SUSPICIOUS", "DATE_CONFLICT"]) == "SUCCESS"
    test_id = read(client, "list_adversarial_tests", [policy_id, 1, 0, 50])["items"][-1]
    assert write(client, "run_adversarial_test", [test_id]) == "SUCCESS"
    view = read(client, "get_adversarial_test", [test_id])
    assert view["observed_verdict"] == "SUSPICIOUS" and view["passed"] is True
    receipt = read(client, "get_receipt", [view["receipt_id"]])
    assert receipt["panel_state"] == "SKIPPED"
    assert [r["status"] for r in receipt["rows"]] == ["EXAMINED"] * 6
