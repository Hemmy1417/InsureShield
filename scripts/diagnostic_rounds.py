"""Disposable diagnostic deployment: which fields split validators on
panel-decided cases? Not canonical; results inform the design only."""
import importlib.util, json, pathlib, sys, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import studionet_transport  # noqa
from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW = sys.argv[2] if len(sys.argv) > 2 else "https://raw.githubusercontent.com/Hemmy1417/InsureShield/aa01aa225467f074b9adbbb15151002d4e319a6c/fixtures/"
OUT = ROOT / "deploy" / "diagnostics" / "last_run.json"
CASES = sys.argv[1].split(",") if len(sys.argv) > 1 else ["L-01", "L-01", "L-02", "A-07", "A-10", "A-11", "A-13"]
spec = importlib.util.spec_from_file_location("support", ROOT / "tests/direct/support.py")
support = importlib.util.module_from_spec(spec); spec.loader.exec_module(support)
client = create_client(chain=studionet, account=create_account())
out = {"rounds": []}


def wait(tx):
    r = client.wait_for_transaction_receipt(transaction_hash=tx, status=TransactionStatus.FINALIZED,
                                            interval=5000, retries=240)
    return r


def leader(r):
    lr = r["consensus_data"]["leader_receipt"]
    return str((lr[0] if isinstance(lr, list) else lr)["execution_result"])


tx = client.deploy_contract(code=(ROOT / "contracts/insureshield.py").read_text(encoding="utf-8"),
                            args=[], consensus_max_rotations=3)
r = wait(tx)
addr = r["data"]["contract_address"]
out["address"] = addr
print("deployed", addr, leader(r), flush=True)
W = lambda fn, args: wait(client.write_contract(address=addr, function_name=fn, args=args,
                                                consensus_max_rotations=3))
R = lambda fn, args: client.read_contract(address=addr, function_name=fn, args=args)
r = W("create_policy", [json.dumps(support.policy_definition(prefix=RAW + "registry/"))])
print("policy", leader(r), flush=True)
for cid in CASES:
    entry = support.case(cid)
    kinds, urls, hashes = support.evidence_lists(entry["claim"], RAW)
    payload = json.dumps({"claim_description": entry["claim"]["claim_description"],
                          "incident_date": entry["claim"]["incident_date"],
                          "claimed_amount": entry["claim"]["claimed_amount"],
                          "evidence": [{"kind": kinds[i], "url": urls[i], "sha256": hashes[i]}
                                       for i in range(len(kinds))]})
    ind = entry["expected_indicators"][0] if entry["expected_indicators"] else ""
    W("register_adversarial_test", ["POL-000001", 1, entry["test_type"], entry["title"], payload,
                                    entry["expected_property"], ind])
    test_id = R("list_adversarial_tests", ["POL-000001", 1, 0, 50])["items"][-1]
    t0 = time.time()
    r = W("run_adversarial_test", [test_id])
    cd = r["consensus_data"]
    nodes = []
    for n in [cd["leader_receipt"][0]] + cd["validators"]:
        nc = n["node_config"]
        nodes.append({"mode": n["mode"], "model": (nc.get("primary_model") or {}).get("model"),
                      "vote": cd["votes"].get(nc["address"]),
                      "stdout": ((n.get("genvm_result") or {}).get("stdout") or "")[-300:]})
    view = R("get_adversarial_test", [test_id])
    rec = R("get_receipt", [view["receipt_id"]]) if view["receipt_id"] else {}
    entry_out = {"case": cid, "status": r.get("status_name"), "leader": leader(r),
                 "seconds": round(time.time() - t0), "observed": view["observed_verdict"],
                 "passed": view["passed"], "indicators": view["observed_indicators"],
                 "states": [(f["id"], f["state"]) for f in rec.get("criteria", []) + rec.get("exclusions", [])
                            + rec.get("indicators", []) if f.get("by") == "PANEL"],
                 "nodes": nodes}
    out["rounds"].append(entry_out)
    OUT.write_text(json.dumps(out, indent=1))
    print(cid, entry_out["status"], entry_out["observed"], entry_out["passed"], entry_out["seconds"], "s",
          [(n["model"], n["vote"], n["stdout"].strip()[-120:]) for n in nodes], flush=True)
print("DONE", flush=True)
