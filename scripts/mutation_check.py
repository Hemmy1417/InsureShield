#!/usr/bin/env python3
"""Mutation kill check: prove the Direct Mode suite pins each load-bearing
guard, not merely that the code passes today.

For each mutation the contract is copied to a scratch directory with ONE
guard mechanically broken, and the whole Direct Mode suite runs against the
copy. A mutation is KILLED when the suite fails and SURVIVED when it passes
(an unpinned guard). The run starts with an accept-control: the unmodified
copy must pass, or every kill would be vacuous.

Anchors are code TEXT, never line numbers. An anchor that is not found
exactly once is reported as ANCHOR MISSING - the guard moved or was
deleted, which is its own finding. Equivalent mutants (a guard that a second
guard makes unobservable) are not listed; the ones considered and excluded
are named at the bottom of this file with the reason.

Run:  python scripts/mutation_check.py            (full sweep)
      python scripts/mutation_check.py --anchors  (anchor check only)
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = "contracts/insureshield.py"

MUTATIONS = [
    # -- verdict derivation ---------------------------------------------------------
    ("hard facts no longer SUSPICIOUS",
     "    if any(i in HARD_FACT_INDICATORS for i in present):\n",
     "    if False:\n"),
    ("hard facts outranked by an unreachable document",
     "    if any(i in HARD_FACT_INDICATORS for i in present):\n",
     "    if any(i in HARD_FACT_INDICATORS for i in present) and ROW_UNAVAILABLE not in statuses:\n"),
    ("unreachable document no longer UNAVAILABLE",
     "    elif ROW_UNAVAILABLE in statuses:\n",
     "    elif False:\n"),
    ("panel manipulation outranks an unreachable document",
     "    elif ROW_UNAVAILABLE in statuses:\n",
     "    elif ROW_UNAVAILABLE in statuses and not any(i in SUSPICIOUS_PANEL_INDICATORS for i in present):\n"),
    ("changed document no longer UNAVAILABLE",
     "    elif ROW_HASH_MISMATCH in statuses:\n",
     "    elif False:\n"),
    ("malformed document no longer INCONCLUSIVE",
     "    elif ROW_TOO_LARGE in statuses or ROW_UNPARSEABLE in statuses:\n",
     "    elif False:\n"),
    ("unusable model output no longer INCONCLUSIVE",
     "    elif payload[\"panel_state\"] == PANEL_INVALID:\n",
     "    elif False:\n"),
    ("panel manipulation indicator no longer SUSPICIOUS",
     "    elif any(i in SUSPICIOUS_PANEL_INDICATORS for i in present):\n",
     "    elif False:\n"),
    ("contradiction no longer INCONCLUSIVE",
     "    elif any(i in CONTRADICTION_INDICATORS for i in present):\n",
     "    elif False:\n"),
    ("contradiction outranked by an applying exclusion",
     "    elif any(i in CONTRADICTION_INDICATORS for i in present):\n",
     "    elif any(i in CONTRADICTION_INDICATORS for i in present) and not any(f[\"state\"] == APPLIES for f in payload[\"exclusions\"]):\n"),
    ("applying exclusion no longer REJECTED",
     "    elif critical_unmet or any(f[\"state\"] == APPLIES\n",
     "    elif critical_unmet or any(False\n"),
    ("critical criterion unmet no longer REJECTED",
     "    critical_unmet = any(f[\"state\"] == NOT_SATISFIED\n",
     "    critical_unmet = False and any(f[\"state\"] == NOT_SATISFIED\n"),
    ("non-critical criterion unmet no longer INCONCLUSIVE",
     "    elif other_unmet:\n",
     "    elif False:\n"),
    ("undecided findings no longer INCONCLUSIVE",
     "    elif undecided:\n        verdict, severity, failure",
     "    elif False:\n        verdict, severity, failure"),
    ("undetermined indicators ignored",
     "        or any(f[\"state\"] == UNDETERMINED for f in indicators)\n",
     "        or False\n"),
    # -- admission --------------------------------------------------------------------
    ("policy amount limit not enforced",
     "    if ctx[\"claimed_amount\"] > policy[\"maximum_claim_amount\"]:\n",
     "    if False:\n"),
    ("coverage start not enforced",
     "    if ctx[\"incident_date\"] < policy[\"coverage_start\"] \\\n",
     "    if False \\\n"),
    ("coverage end not enforced",
     "            or ctx[\"incident_date\"] > policy[\"coverage_end\"]:\n",
     "            or False:\n"),
    ("late notice not enforced",
     "    if delay > policy[\"reporting_window_days\"]:\n",
     "    if False:\n"),
    ("reporting window off by one",
     "    if delay > policy[\"reporting_window_days\"]:\n",
     "    if delay >= policy[\"reporting_window_days\"]:\n"),
    # -- hard facts in code -------------------------------------------------------------
    ("line-item arithmetic not checked",
     "        [f[\"evidence_id\"] for f in facts if f[\"line_sum\"] != f[\"total\"]],\n",
     "        [],\n"),
    ("claim above the documented amount not flagged",
     "        if claimed > documented:\n",
     "        if False:\n"),
    ("excluded invoice falls back to the estimate",
     "    if len(committed_invoices) > 0:\n",
     "    if len(invoices) > 0:\n"),
    ("inflation computed over part of the invoices",
     "    elif not _all_examined(rows, basis_committed) or len(basis) == 0:\n",
     "    elif len(basis) == 0:\n"),
    ("estimate tolerance ignored",
     "        if invoiced * BPS_MAX > estimated * (BPS_MAX + bps):\n",
     "        if invoiced * BPS_MAX > estimated * BPS_MAX:\n"),
    ("estimate overrun not flagged",
     "        if invoiced * BPS_MAX > estimated * (BPS_MAX + bps):\n",
     "        if False:\n"),
    ("document predating the incident not flagged",
     "         if f[\"issue_date\"] < ctx[\"incident_date\"]\n",
     "         if False\n"),
    ("document postdating submission not flagged",
     "         or f[\"issue_date\"] > ctx[\"submitted_on\"]],\n",
     "         or False],\n"),
    ("injection markers not scanned",
     "        if _injection_hits(texts[eid]):\n",
     "        if False:\n"),
    ("hard fact ABSENT over an unexamined document",
     "    if not _all_examined(rows, committed):\n        return _finding(name, UNDETERMINED, BY_CODE)\n",
     "    if False:\n        return _finding(name, UNDETERMINED, BY_CODE)\n"),
    ("amount criterion computed over part of the record",
     "        if len(used) == 0 or not _all_examined(rows, committed):\n",
     "        if len(used) == 0:\n"),
    # -- when the panel is convened, and on what ------------------------------------
    ("panel convened on a partial record",
     "    if any(r[\"status\"] != ROW_EXAMINED for r in rows):\n        skip = SKIP_NOT_EXAMINED\n",
     "    if False:\n        skip = SKIP_NOT_EXAMINED\n"),
    ("panel convened despite a hard fact",
     "    elif any(f[\"state\"] == PRESENT for f in code_inds):\n",
     "    elif False:\n"),
    ("trusted-only criterion accepts any source",
     "        if trusted_only and not it[\"trusted\"]:\n",
     "        if False:\n"),
    ("semantic criterion with no eligible document asked anyway",
     "    if len(eligible) == 0:\n        return (_finding(cid, UNVERIFIABLE, BY_CODE), eligible)\n    return (None, eligible)\n",
     "    return (None, eligible)\n"),
    ("indicator eligibility ignored",
     "    for group in requires:\n",
     "    for group in ():\n"),
    # -- grounding ---------------------------------------------------------------------
    ("quotes not checked against the verified bytes",
     "        position = _find_run(haystack, words, position)\n        if position < 0:\n            return False\n",
     "        position = 0\n"),
    ("quote fragments may appear out of order",
     "        position = _find_run(haystack, words, position)\n",
     "        position = _find_run(haystack, words, 0)\n"),
    ("one-word quotes accepted",
     "    if len(fragments) == 0 or sum(len(f) for f in fragments) < 2:\n",
     "    if len(fragments) == 0:\n"),
    ("quote words need not be contiguous",
     "        if haystack[i:i + len(needle)] == needle:\n",
     "        if all(w in haystack for w in needle):\n"),
    ("quotes from ineligible documents accepted",
     "    if quote[\"evidence_id\"] not in eligible:\n        return False\n    if texts is None:\n",
     "    if texts is None:\n"),
    ("model SATISFIED kept without a quote",
     "        if state is None or (state == SATISFIED and len(quotes) == 0):\n",
     "        if state is None:\n"),
    ("model APPLIES kept without a quote",
     "        if state is None or (state == APPLIES and len(quotes) == 0):\n",
     "        if state is None:\n"),
    ("gate accepts SATISFIED without a quote",
     "        if fixed is None and criteria[i][\"state\"] == SATISFIED \\\n",
     "        if False and criteria[i][\"state\"] == SATISFIED \\\n"),
    ("gate accepts APPLIES without a quote",
     "        if fixed is None and exclusions[i][\"state\"] == APPLIES \\\n",
     "        if False and exclusions[i][\"state\"] == APPLIES \\\n"),
    ("gate accepts PRESENT without its quote rule",
     "        if fixed is None and f[\"state\"] == PRESENT \\\n",
     "        if False and f[\"state\"] == PRESENT \\\n"),
    ("quote rule ignores the number of documents",
     "    if len(distinct) < min_docs:\n",
     "    if False:\n"),
    ("quote rule ignores the document kind",
     "    if len(quote_kinds) > 0 and not any(kinds[e] in quote_kinds for e in distinct):\n",
     "    if False:\n"),
    ("gate does not recompute code indicators",
     "        if indicators[i] != plan[\"code_indicators\"][i]:\n",
     "        if False:\n"),
    # -- the validator -----------------------------------------------------------------
    ("validator ratifies without reproducing",
     "        own, own_texts = reproduce()\n        parsed = _parse_payload(leader_res.calldata, ctx, own_texts)\n",
     "        return _parse_payload(leader_res.calldata, ctx, None) is not None\n        parsed = None\n"),
    ("validator gates without its own bytes",
     "        parsed = _parse_payload(leader_res.calldata, ctx, own_texts)\n",
     "        parsed = _parse_payload(leader_res.calldata, ctx, None)\n"),
    ("finding states not compared",
     "            if a[\"id\"] != b[\"id\"] or a[\"state\"] != b[\"state\"] or a[\"by\"] != b[\"by\"]:\n",
     "            if a[\"id\"] != b[\"id\"]:\n"),
    ("rows not compared",
     "        if a[\"status\"] != b[\"status\"] or a[\"byte_count\"] != b[\"byte_count\"]:\n",
     "        if False:\n"),
    ("facts not compared",
     "    if own[\"markers\"] != theirs[\"markers\"] or own[\"facts\"] != theirs[\"facts\"]:\n",
     "    if own[\"markers\"] != theirs[\"markers\"]:\n"),
    ("markers not compared",
     "    if own[\"markers\"] != theirs[\"markers\"] or own[\"facts\"] != theirs[\"facts\"]:\n",
     "    if own[\"facts\"] != theirs[\"facts\"]:\n"),
    ("panel state not compared",
     "    if own[\"panel_state\"] != theirs[\"panel_state\"] \\\n",
     "    if False \\\n"),
    ("transient leader errors ratified unconditionally",
     "            return own_text.startswith(ERROR_TRANSIENT)\n",
     "            return True\n"),
    ("model errors may be ratified",
     "    if leader_text.startswith(ERROR_LLM):\n        return False\n",
     ""),
    ("boundary does not regate ratified text",
     "        payload = _parse_payload(ratified, ctx, None)\n        if payload is None:\n",
     "        payload = json.loads(ratified)\n        if payload is None:\n"),
    # -- evidence integrity --------------------------------------------------------------
    ("content hash not verified",
     "    if hashlib.sha256(body).hexdigest() != item[\"sha256\"]:\n",
     "    if False:\n"),
    ("size bound removed",
     "    if len(body) > FETCH_BYTES_CAP:\n",
     "    if False:\n"),
    ("HTTP status ignored",
     "    if status < 200 or status >= 300 or body is None or len(body) == 0:\n",
     "    if body is None or len(body) == 0:\n"),
    ("structured schema not enforced",
     "            if _structured_facts(text, item[\"kind\"], item[\"evidence_id\"]) is None:\n",
     "            if False:\n"),
    ("non-integer amounts accepted",
     "    if not _is_int(total) or total < 0 or total > AMOUNT_MAX:\n",
     "    if total < 0 or total > AMOUNT_MAX:\n"),
    ("booleans accepted as integers",
     "    return isinstance(value, int) and not isinstance(value, bool)\n",
     "    return isinstance(value, int)\n"),
    # -- URL admission -------------------------------------------------------------------
    ("plain http accepted",
     "    if not url.startswith(\"https://\"):\n",
     "    if not url.startswith(\"http\"):\n"),
    ("embedded credentials accepted",
     "    if \"@\" in authority:\n",
     "    if False:\n"),
    ("unexpected ports accepted",
     "        if port != \"443\":\n",
     "        if False:\n"),
    ("IP literals accepted",
     "    if all_numeric or labels[-1].isdigit():\n",
     "    if False:\n"),
    ("localhost accepted",
     "    if host == \"localhost\" or host.endswith(\".localhost\"):\n",
     "    if False:\n"),
    ("internal names accepted",
     "    if host.endswith(\".local\") or host.endswith(\".internal\") \\\n",
     "    if False and host.endswith(\".internal\") \\\n"),
    ("dot-segments accepted",
     "        if seg in (\".\", \"..\"):\n",
     "        if False:\n"),
    ("encoded separators accepted",
     "    if \"%2e\" in lowered or \"%2f\" in lowered or \"%5c\" in lowered:\n",
     "    if False:\n"),
    ("fragments accepted",
     "    if \"#\" in rest:\n",
     "    if False:\n"),
    ("trusted prefix need not end at a path boundary",
     "    if \"?\" in canonical or not canonical.endswith(\"/\"):\n",
     "    if \"?\" in canonical:\n"),
    # -- evidence lists ------------------------------------------------------------------
    ("relocated document may change kind",
     "            if match[\"kind\"] != kind:\n",
     "            if False:\n"),
    ("same document twice accepted",
     "            if match.get(\"_touched\", False):\n",
     "            if False:\n"),
    ("same location twice accepted",
     "        if it[\"url\"] in urls_seen:\n",
     "        if False:\n"),
    ("evidence maximum not enforced",
     "    if len(items) > definition[\"maximum_evidence_count\"]:\n",
     "    if False:\n"),
    ("evidence minimum not enforced",
     "    if minimum_applies and len(items) < definition[\"minimum_evidence_count\"]:\n",
     "    if False:\n"),
    # -- lifecycle -------------------------------------------------------------------------
    ("terminal claim resolvable again",
     "        if str(claim.status) != CLAIM_PENDING:\n",
     "        if False:\n"),
    ("retry cooldown not enforced",
     "        if _iso_epoch(now) < int(claim.next_retry_at):\n",
     "        if False:\n"),
    ("anyone may retry a claim",
     "        if gl.message.sender_address != claim.claimant:\n            self._fail(\"only the claimant can retry a claim\")\n",
     ""),
    ("rounds unbounded",
     "        if verdict in TERMINAL_VERDICTS or round_no >= MAX_ROUNDS:\n",
     "        if verdict in TERMINAL_VERDICTS:\n"),
    ("inconclusive made terminal",
     "        if verdict in TERMINAL_VERDICTS or round_no >= MAX_ROUNDS:\n",
     "        if True:\n"),
    ("claim reference replay accepted",
     "        if self.reference_index.get(ref_key) is not None:\n",
     "        if False:\n"),
    ("anyone may publish a policy version",
     "        if gl.message.sender_address != latest.owner:\n",
     "        if False:\n"),
    ("claims resolved under the latest version, not their own",
     "        pv = self._policy(str(claim.policy_id), int(claim.policy_version))\n        definition = json.loads(str(pv.definition))\n        now = self._now()\n",
     "        pv = self._policy(str(claim.policy_id), int(self.policy_heads.get(str(claim.policy_id))))\n        definition = json.loads(str(pv.definition))\n        now = self._now()\n"),
    # -- freshness and consumability ------------------------------------------------------
    ("non-VALID verdicts consumable",
     "        if str(claim.status) != CLAIM_RESOLVED or str(claim.verdict) != VALID:\n            return False\n",
     "        if str(claim.status) != CLAIM_RESOLVED:\n            return False\n"),
    ("later duplicate still consumable",
     "        if self._later_duplicate_of(claim) != \"\":\n            return False\n",
     ""),
    ("receipt validity not enforced",
     "        if at > created + definition[\"receipt_validity_seconds\"]:\n",
     "        if False:\n"),
    ("freshness asserted before the receipt existed",
     "        if at is None or at < created:\n",
     "        if at is None:\n"),
    ("unavailable evidence reported fresh",
     "        if receipt[\"verdict\"] == UNAVAILABLE:\n",
     "        if False:\n"),
    # -- duplicate registries --------------------------------------------------------------
    ("a claim is its own duplicate",
     "        if ctx[\"mode\"] == MODE_CLAIM and first == ctx[\"subject_id\"]:\n",
     "        if False:\n"),
    ("own cancelled claim counts as a duplicate",
     "        if ctx[\"mode\"] == MODE_CLAIM and str(rec.status) == CLAIM_CANCELLED \\\n",
     "        if False and str(rec.status) == CLAIM_CANCELLED \\\n"),
    ("cancel-and-resubmit launders a judged claim",
     "                and _addr_hex(rec.claimant) == ctx[\"claimant\"] \\\n                and len(rec.receipt_ids) == 0:\n",
     "                and _addr_hex(rec.claimant) == ctx[\"claimant\"]:\n"),
    ("ownership records flagged as duplicates",
     "        if item[\"kind\"] == \"OWNERSHIP_RECORD\" and \\\n",
     "        if False and \\\n"),
    ("relabelling a reused invoice escapes",
     "                self._first_kind(first, item[\"sha256\"]) == \"OWNERSHIP_RECORD\":\n",
     "                True:\n"),
    ("document numbers not normalized",
     "    return kind + \"|\" + _norm_key(issuer) + \"|\" + _norm_key(number)\n",
     "    return kind + \"|\" + issuer + \"|\" + number\n"),
    ("document numbers ordered by resolution",
     "            earlier = mine is None or first_seq < mine\n",
     "            earlier = True\n"),
    ("registry keeps the first resolver, not the earliest commitment",
     "                if entry is None or item[\"committed_seq\"] < entry[0]:\n",
     "                if entry is None:\n"),
    # -- the adversarial-test engine -------------------------------------------------------
    ("safety property always holds",
     "    return verdict == expected[len(\"VERDICT_\"):]\n",
     "    return True\n"),
    ("expected indicator ignored",
     "            holds = holds and str(test.expected_indicator) in present\n",
     "            holds = holds\n"),
    ("a test may run twice",
     "        if str(test.status) != TEST_REGISTERED:\n",
     "        if False:\n"),
    # -- definitions -----------------------------------------------------------------------
    ("definition key set not enforced",
     "    if not isinstance(d, dict) or sorted(d.keys()) != sorted(DEFINITION_KEYS):\n",
     "    if not isinstance(d, dict):\n"),
    ("trusted-only criterion without a trusted source",
     "        if c[\"trusted_only\"] and len(trusted) == 0:\n",
     "        if False:\n"),
]

# Considered and excluded as equivalent (a second guard makes the first
# unobservable, so no test can tell the mutant from the original):
# - "revoked version consumable" in _consumable: _freshness already returns
#   STALE for a revoked version, so is_consumable is false either way.
# - the definition_hash cross-checks in _consumable: the claim, its receipt
#   and its version are written from the same value and never rewritten.


def run_suite(workdir: pathlib.Path) -> bool:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/direct", "-q", "-x",
         "-p", "no:cacheprovider", "--no-header"],
        cwd=workdir, capture_output=True, text=True)
    return completed.returncode == 0


def check_anchors(source: str) -> int:
    missing = 0
    for name, old, _new in MUTATIONS:
        hits = source.count(old)
        if hits != 1:
            print(f"ANCHOR MISSING ({hits} hits): {name}")
            missing += 1
    return missing


def main() -> None:
    source = (ROOT / CONTRACT).read_text(encoding="utf-8")
    missing = check_anchors(source)
    print(f"{len(MUTATIONS)} mutations, {missing} anchor problems")
    if "--anchors" in sys.argv:
        sys.exit(0 if missing == 0 else 1)

    scratch = pathlib.Path(tempfile.mkdtemp(prefix="insureshield-mut-"))
    work = scratch / "repo"
    shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", ".pytest_cache", "deploy", "artifacts"))
    target = work / CONTRACT

    print("accept-control: unmodified copy must pass ...", flush=True)
    if not run_suite(work):
        print("CONTROL FAILED: the unmodified suite does not pass; aborting")
        sys.exit(1)
    print("control green\n", flush=True)

    killed = survived = 0
    for name, old, new in MUTATIONS:
        if source.count(old) != 1:
            continue
        target.write_text(source.replace(old, new), encoding="utf-8", newline="\n")
        passed = run_suite(work)
        target.write_text(source, encoding="utf-8", newline="\n")
        if passed:
            print(f"SURVIVED: {name}", flush=True)
            survived += 1
        else:
            print(f"killed:   {name}", flush=True)
            killed += 1
    shutil.rmtree(scratch, ignore_errors=True)
    print(f"\nmutations: {killed} killed, {survived} survived, {missing} anchor missing")
    sys.exit(0 if survived == 0 and missing == 0 else 1)


if __name__ == "__main__":
    main()
