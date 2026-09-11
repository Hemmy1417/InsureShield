#!/usr/bin/env python3
"""Live StudioNet run against an InsureShield deployment: real consensus,
real web fetches of commit-pinned evidence, a real model on the panel.

  python scripts/live_scenarios.py <address> --raw-base <url> [--only T,R,C]

  --raw-base  https://raw.githubusercontent.com/<owner>/<repo>/<commit>/fixtures/

Phases, in the order the duplicate registry requires (adversarial tests read
the registry but never write it, so they run before any real claim):

  T  adversarial suite: the insurer creates policy v1 and registers every
     live fixture case (fixtures/*.json, "live": true) as an on-chain test;
     a stranger runs each one. Each test records whether its safety
     property held.
  R  rule change: v2 tightens the estimate tolerance to 5%; the legitimate
     baseline replayed onto v2 now fails (a false positive the insurer sees
     before adopting the change); v3 restores 15% and the baseline and the
     overrun attack are replayed onto it.
  C  real claims on v3: a legitimate claim (VALID, consumable); the same
     documents claimed by a second claimant (SUSPICIOUS via the registry);
     a claim whose photo log is unreachable (UNAVAILABLE, RETRYABLE), then
     relocated to its real location after the cooldown and resolved again.
     Plus live refusals.

What is ASSERTED (the run fails without it) versus RECORDED: every
transaction's leader execution result, every code- and registry-decided
outcome, every refusal. Panel-decided outcomes depend on a real model's
reading; they are recorded with the observed verdict, and the summary lists
each one as held or not held. Nothing is asserted about model prose.

Driver accounts are ephemeral (StudioNet is gasless) and kept in
.data/live_accounts.json (gitignored) so an interrupted run can resume.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import time
import urllib.error
import urllib.request

import studionet_transport  # noqa: F401 - retries RPC transport failures
from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
ACCOUNTS = ROOT / ".data" / "live_accounts.json"
OUT = ROOT / "deploy" / "live_scenarios_transcript.json"
WAIT = dict(interval=5000, retries=240)
TRANSCRIPT: dict = {"network": "studionet", "phases": {}}


def log(*parts):
    print(*parts, flush=True)


def save():
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(TRANSCRIPT, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8", newline="\n")


def die(message: str):
    log("FATAL:", message)
    TRANSCRIPT["fatal"] = message
    save()
    raise SystemExit(1)


def retry(action, attempts=8, pause=20):
    last = None
    for attempt in range(attempts):
        try:
            return action()
        except Exception as err:          # noqa: BLE001 - transport errors vary
            last = err
            log(f"    transient ({attempt + 1}/{attempts}): {str(err)[:120]}")
            time.sleep(pause)
    raise last


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


LEGIT = load_fixture("legitimate_claims.json")
ADVERSARIAL = load_fixture("adversarial_claims.json")
CASES = {c["case_id"]: c for c in LEGIT["cases"] + ADVERSARIAL["cases"]}


def sha(rel: str) -> str:
    return hashlib.sha256((FIXTURES / rel).read_bytes()).hexdigest()


def evidence(entry: dict, raw: str) -> list:
    return [{"kind": e["kind"], "url": raw + e["file"],
             "sha256": sha(e.get("sha256_of", e["file"]))}
            for e in entry["claim"]["evidence"]]


def verify_fixtures(raw: str):
    """Every file a live case expects to be reachable must serve exactly the
    local bytes; every file under evidence/moved/ must NOT be reachable."""
    files = set()
    for entry in CASES.values():
        for e in entry["claim"]["evidence"]:
            files.add(e["file"])
    for rel in sorted(files):
        url = raw + rel
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                body = response.read()
            reachable = True
        except urllib.error.HTTPError:
            reachable = False
        if rel.startswith("evidence/moved/"):
            if reachable:
                die(f"{url} should be unreachable")
            log(f"  unreachable as intended: {rel}")
            continue
        if not reachable or hashlib.sha256(body).hexdigest() != sha(rel):
            die(f"{url} does not serve the committed bytes")
        log(f"  verified {rel} ({len(body)} bytes)")


def leader_result(receipt) -> str:
    leader = receipt["consensus_data"]["leader_receipt"]
    entry = leader[0] if isinstance(leader, list) else leader
    return str(entry["execution_result"])


def votes(receipt) -> list:
    last_round = receipt.get("last_round") or {}
    named = last_round.get("validator_votes_name")
    if named:
        return [str(v) for v in named]
    mapping = (receipt.get("consensus_data") or {}).get("votes") or {}
    return [str(v).upper() for v in mapping.values()]


def status_name(receipt) -> str:
    return str(receipt.get("status_name") or receipt.get("status") or "")


class Actor:
    def __init__(self, address: str, name: str, key: str):
        self.name = name
        self.address = address
        self.account = create_account(key)
        self.client = create_client(chain=studionet, account=self.account)
        self.me = str(self.account.address)
        log(f"{name}: {self.me}")

    def read(self, fn: str, args: list):
        return retry(lambda: self.client.read_contract(
            address=self.address, function_name=fn, args=args))

    def write(self, fn: str, args: list, expect: str = "SUCCESS") -> dict:
        tx = self.client.write_contract(address=self.address, function_name=fn,
                                        args=args, consensus_max_rotations=3)
        tx = tx if isinstance(tx, str) else tx.hex()
        log(f"  {self.name}.{fn} tx {tx}")
        receipt = retry(lambda: self.client.wait_for_transaction_receipt(
            transaction_hash=tx, status=TransactionStatus.FINALIZED, **WAIT))
        result = leader_result(receipt)
        record = {"tx": tx, "status": status_name(receipt),
                  "leader_execution": result, "votes": votes(receipt)}
        log(f"    {record['status']} leader {result} votes {record['votes']}")
        if result != expect:
            die(f"{fn}: leader execution {result}, expected {expect}")
        return record


def accounts(address: str) -> dict:
    ACCOUNTS.parent.mkdir(exist_ok=True)
    keys = json.loads(ACCOUNTS.read_text()) if ACCOUNTS.exists() else {}
    for role in ("insurer", "claimant", "fraudster", "stranger"):
        if role not in keys:
            keys[role] = create_account().key.hex()
    ACCOUNTS.write_text(json.dumps(keys))
    return {role: Actor(address, role, key) for role, key in keys.items()}


def definition(raw: str, **overrides) -> str:
    """The same canonical motor policy the Direct Mode suite uses, with the
    trusted source pinned to this commit's registry folder."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "support", ROOT / "tests" / "direct" / "support.py")
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    return json.dumps(support.policy_definition(prefix=raw + "registry/", **overrides))


def summarize(receipt: dict) -> dict:
    return {
        "verdict": receipt["verdict"], "severity": receipt["severity"],
        "failure_class": receipt["failure_class"],
        "confidence_band": receipt["confidence_band"],
        "panel_state": receipt["panel_state"], "panel_reason": receipt["panel_reason"],
        "rows": [(r["evidence_id"], r["status"]) for r in receipt["rows"]],
        "present": [f["id"] for f in receipt["indicators"] if f["state"] == "PRESENT"],
        "criteria": [(f["id"], f["state"], f["by"]) for f in receipt["criteria"]],
        "exclusions": [(f["id"], f["state"]) for f in receipt["exclusions"]],
        "reason_codes": receipt["reason_codes"],
        "record_digest": receipt["record_digest"],
    }


def attack_payload(entry: dict, raw: str) -> str:
    return json.dumps({
        "claim_description": entry["claim"]["claim_description"],
        "incident_date": entry["claim"]["incident_date"],
        "claimed_amount": entry["claim"]["claimed_amount"],
        "evidence": evidence(entry, raw),
    })


def run_test(insurer: Actor, stranger: Actor, test_id: str, entry: dict) -> dict:
    record = {"test_id": test_id, "case_id": entry["case_id"],
              "decided_by": entry["decided_by"],
              "expected_property": entry["expected_property"],
              "expected_indicators": entry["expected_indicators"]}
    record["run"] = stranger.write("run_adversarial_test", [test_id])
    view = insurer.read("get_adversarial_test", [test_id])
    record["observed_verdict"] = view["observed_verdict"]
    record["observed_indicators"] = view["observed_indicators"]
    record["passed"] = view["passed"]
    record["receipt"] = summarize(insurer.read("get_receipt", [view["receipt_id"]]))
    held = "HELD" if view["passed"] else "NOT HELD"
    log(f"    {entry['case_id']} {view['observed_verdict']} "
        f"{view['observed_indicators']} -> property {held}")
    if entry["decided_by"] in ("CODE", "ADMISSION", "REGISTRY") and not view["passed"]:
        die(f"{entry['case_id']}: a code-decided safety property did not hold")
    return record


def phase_tests(actors: dict, raw: str) -> dict:
    insurer, stranger = actors["insurer"], actors["stranger"]
    log("\nPHASE T - the adversarial suite on-chain (policy v1)")
    phase = {"create_policy": insurer.write("create_policy", [definition(raw)])}
    stats = insurer.read("get_stats", [])
    policy_id = "POL-" + str(stats["policies"]).zfill(6)
    view = insurer.read("get_policy", [policy_id, 1])
    if view["owner"].lower() != insurer.me.lower():
        die("policy owner mismatch")
    phase["policy_id"] = policy_id
    phase["definition_hash_v1"] = view["definition_hash"]
    phase["refusal_stranger_registers_test"] = stranger.write(
        "register_adversarial_test",
        [policy_id, 1, "OTHER", "x", attack_payload(CASES["A-01"], raw),
         "NOT_VALID", ""], expect="ERROR")
    live = [c for c in CASES.values() if c["live"] and "requires_prior" not in c]
    phase["tests"] = []
    for entry in live:
        indicator = entry["expected_indicators"][0] if entry["expected_indicators"] else ""
        registered = insurer.write("register_adversarial_test", [
            policy_id, 1, entry["test_type"], entry["title"],
            attack_payload(entry, raw), entry["expected_property"], indicator])
        tests = insurer.read("list_adversarial_tests", [policy_id, 1, 0, 50])
        test_id = tests["items"][-1]
        record = run_test(insurer, stranger, test_id, entry)
        record["register"] = registered
        phase["tests"].append(record)
        TRANSCRIPT["phases"]["T"] = phase
        save()
    return phase


def phase_rules(actors: dict, raw: str, policy_id: str, tests: list) -> dict:
    insurer, stranger = actors["insurer"], actors["stranger"]
    log("\nPHASE R - evaluating a rule change against recorded attacks")
    phase = {"refusal_stranger_publishes": stranger.write(
        "publish_policy_version", [policy_id, definition(raw)], expect="ERROR")}
    by_case = {t["case_id"]: t["test_id"] for t in tests}
    phase["publish_v2"] = insurer.write(
        "publish_policy_version", [policy_id, definition(raw, estimate_tolerance_bps=500)])
    replay = insurer.write("replay_adversarial_test", [by_case["L-01"], 2])
    v2_tests = insurer.read("list_adversarial_tests", [policy_id, 2, 0, 50])["items"]
    phase["baseline_on_v2"] = run_test(insurer, stranger, v2_tests[-1], CASES["L-01"])
    phase["baseline_on_v2"]["replay"] = replay
    if phase["baseline_on_v2"]["passed"] or \
            "ESTIMATE_EXCEEDED" not in phase["baseline_on_v2"]["observed_indicators"]:
        die("the tightened rule should flag the legitimate baseline (6.4% overrun)")
    log("  v2 flags the legitimate baseline: the change would create a false positive")
    phase["publish_v3"] = insurer.write("publish_policy_version", [policy_id, definition(raw)])
    phase["on_v3"] = []
    for case_id in ("L-01", "A-04"):
        replay = insurer.write("replay_adversarial_test", [by_case[case_id], 3])
        v3_tests = insurer.read("list_adversarial_tests", [policy_id, 3, 0, 50])["items"]
        record = run_test(insurer, stranger, v3_tests[-1], CASES[case_id])
        record["replay"] = replay
        phase["on_v3"].append(record)
    TRANSCRIPT["phases"]["R"] = phase
    save()
    return phase


def submit(actor: Actor, policy_id: str, entry: dict, raw: str, reference: str,
           overrides: dict = None) -> tuple:
    items = evidence(entry, raw)
    for index, url in (overrides or {}).items():
        items[index]["url"] = url
    record = actor.write("submit_claim", [
        policy_id, reference, entry["claim"]["claim_description"],
        entry["claim"]["incident_date"], entry["claim"]["claimed_amount"],
        [i["kind"] for i in items], [i["url"] for i in items],
        [i["sha256"] for i in items]])
    claim_id = "CLM-" + str(actor.read("get_stats", [])["claims"]).zfill(6)
    view = actor.read("get_claim", [claim_id])
    if view["claim_reference"] != reference:
        die(f"claim id lookup mismatch for {reference}")
    return claim_id, record


def resolve(actor: Actor, claim_id: str) -> dict:
    record = actor.write("resolve_claim", [claim_id])
    view = actor.read("get_claim", [claim_id])
    record["claim_status"] = view["status"]
    record["receipt"] = summarize(actor.read("get_receipt", [view["receipt_ids"][-1]]))
    log(f"    {claim_id} {view['status']} {view['verdict']} "
        f"{record['receipt']['present']} {record['receipt']['reason_codes']}")
    return record


def phase_claims(actors: dict, raw: str, policy_id: str) -> dict:
    claimant, fraudster, stranger = actors["claimant"], actors["fraudster"], actors["stranger"]
    log("\nPHASE C - real claims on policy v3")
    phase = {}
    tag = time.strftime("%m%d%H%M", time.gmtime())

    claim_id, phase["legit_submit"] = submit(claimant, policy_id, CASES["L-01"], raw,
                                             "LIVE-L01-" + tag)
    phase["legit_claim_id"] = claim_id
    phase["legit_resolve"] = resolve(stranger, claim_id)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    phase["legit_outcome"] = claimant.read("claim_outcome", [claim_id, now])
    log(f"    outcome: {phase['legit_outcome']}")
    phase["refusal_resolve_twice"] = stranger.write("resolve_claim", [claim_id], expect="ERROR")

    dup_id, phase["duplicate_submit"] = submit(fraudster, policy_id, CASES["L-01"], raw,
                                               "LIVE-DUP-" + tag)
    phase["duplicate_claim_id"] = dup_id
    phase["duplicate_resolve"] = resolve(stranger, dup_id)
    receipt = phase["duplicate_resolve"]["receipt"]
    if receipt["verdict"] != "SUSPICIOUS" or "DUPLICATE_EVIDENCE" not in receipt["present"]:
        die("the duplicate claim should be SUSPICIOUS via the registry")

    entry = copy.deepcopy(CASES["L-02"])
    dead = raw + "evidence/moved/photo_log.txt"
    retry_id, phase["relocation_submit"] = submit(claimant, policy_id, entry, raw,
                                                  "LIVE-L02-" + tag, {5: dead})
    phase["relocation_claim_id"] = retry_id
    phase["relocation_round_1"] = resolve(stranger, retry_id)
    receipt = phase["relocation_round_1"]["receipt"]
    if receipt["verdict"] != "UNAVAILABLE" or \
            phase["relocation_round_1"]["claim_status"] != "RETRYABLE":
        die("the unreachable photo log should leave the claim UNAVAILABLE and RETRYABLE")
    phase["refusal_stranger_retries"] = fraudster.write(
        "retry_claim", [retry_id, [], [], []], expect="ERROR")
    log("    waiting out the retry cooldown (policy: 60 s)")
    time.sleep(75)
    photo = entry["claim"]["evidence"][5]
    phase["relocation_retry"] = claimant.write("retry_claim", [
        retry_id, [photo["kind"]], [raw + photo["file"]], [sha(photo["file"])]])
    phase["relocation_round_2"] = resolve(stranger, retry_id)
    TRANSCRIPT["phases"]["C"] = phase
    save()
    return phase


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("address")
    parser.add_argument("--raw-base", required=True)
    parser.add_argument("--only", default="T,R,C")
    args = parser.parse_args()
    raw = args.raw_base if args.raw_base.endswith("/") else args.raw_base + "/"
    if OUT.exists():
        previous = json.loads(OUT.read_text(encoding="utf-8"))
        if previous.get("contract") == args.address:
            TRANSCRIPT.update(previous)
            TRANSCRIPT.pop("fatal", None)
    TRANSCRIPT["contract"] = args.address
    TRANSCRIPT["raw_base"] = raw
    TRANSCRIPT.setdefault("runs", []).append(
        {"started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "only": args.only})
    log("verifying evidence URLs serve the committed bytes ...")
    verify_fixtures(raw)
    actors = accounts(args.address)
    TRANSCRIPT["accounts"] = {role: a.me for role, a in actors.items()}
    save()
    wanted = [p.strip().upper() for p in args.only.split(",")]
    phase_t = TRANSCRIPT["phases"].get("T")
    if "T" in wanted:
        phase_t = phase_tests(actors, raw)
    if phase_t is None:
        die("phase T must run first (it creates the policy)")
    if "R" in wanted:
        phase_rules(actors, raw, phase_t["policy_id"], phase_t["tests"])
    if "C" in wanted:
        phase_claims(actors, raw, phase_t["policy_id"])
    tests = TRANSCRIPT["phases"]["T"]["tests"] + \
        TRANSCRIPT["phases"].get("R", {}).get("on_v3", [])
    TRANSCRIPT["summary"] = {
        "tests_run": len(tests),
        "properties_held": sum(1 for t in tests if t["passed"]),
        "not_held": [t["case_id"] + " (" + t["decided_by"] + ", observed "
                     + t["observed_verdict"] + ")" for t in tests if not t["passed"]],
    }
    TRANSCRIPT["runs"][-1]["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save()
    log("\nsummary:", json.dumps(TRANSCRIPT["summary"], indent=2))
    log("LIVE RUN COMPLETE (code-decided properties asserted; panel outcomes recorded)")


if __name__ == "__main__":
    main()
