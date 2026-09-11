#!/usr/bin/env python3
"""Preflight: fast structural checks that need no network and no GenVM.

Run before the Direct Mode suite and the linter (CI does). Every check is
named; the script prints PASS/FAIL per check and exits non-zero on any
failure. It proves repository invariants, not contract behaviour.

  python scripts/preflight.py
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "insureshield.py"
FIXTURES = ROOT / "fixtures"
RUNNER = "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6"
FETCH_BYTES_CAP = 12000

# Brief section 11: every attack category and the test that covers it.
CATEGORIES = {
    "fabricated invoice": "test_fixture_case",                         # A-01
    "altered repair estimate": "test_fixture_case",                    # A-02, A-04
    "duplicate claim": "test_fixture_case_after_its_prior_claim",      # A-05, A-06
    "conflicting dates": "test_a_document_dated_after_submission_is_a_date_conflict",
    "conflicting witness statements": "test_witness_conflict_needs_a_witness_quote",
    "fake proof of ownership": "test_code_decided_findings_in_panel_cases",
    "misleading photograph description": "test_leader_valid_while_validator_sees_a_critical_indicator",
    "prompt injection inside evidence": "test_markers_are_compared_not_just_gated",
    "missing required evidence": "test_missing_evidence_is_code_decided",
    "unreachable source": "test_unreachable_row_and_reachability",
    "contradictory policy interpretation": "test_ambiguous_exclusion_applies_only_with_a_quote",
    "oversized or malformed model output": "test_unusable_model_output_is_inconclusive",
    "unknown verdict enum": "test_criterion_answers_are_grounded_or_downgraded",
    "boolean-as-integer confusion": "test_forged_leader_is_refused",
    "float where integer is required": "test_structured_documents_that_break_the_schema",
    "invented evidence URL": "test_forged_leader_is_refused",
    "omitted critical criterion": "test_missing_subject_in_model_output_is_undecided",
    "leader VALID while validator sees a critical indicator": "test_leader_valid_while_validator_sees_a_critical_indicator",
    "leader RELIABLE while validator cannot reach the source": "test_leader_claims_a_source_this_validator_cannot_reach",
    "legitimate claim with unusual context": "test_fixture_case",      # L-02
}

RESULTS = []


def check(name: str, ok: bool, detail: str = ""):
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "  -> " + detail))


def norm(text: str) -> str:
    return " ".join(text.split()).casefold()


def contract_checks():
    raw = CONTRACT.read_bytes()
    lines = raw.decode("utf-8").split("\n")
    check("contract has no CR bytes", b"\r" not in raw)
    check("contract is ASCII", all(b < 128 for b in raw),
          "non-ASCII bytes break hosted schema encoding")
    check("line 1 is the version comment", lines[0] == "# v0.1.0", lines[0])
    check("line 2 pins the runner", lines[1] == '# { "Depends": "' + RUNNER + '" }', lines[1])
    check("line 3 is blank (Depends block is load-bearing)", lines[2] == "")
    text = raw.decode("utf-8")
    for alias in ("py-genlayer:test", "py-genlayer:latest"):
        check("no runner alias " + alias, alias not in text)
    version = re.search(r'^CONTRACT_VERSION = "([^"]+)"', text, re.M)
    check("CONTRACT_VERSION matches the header",
          version is not None and "# v" + version.group(1) == lines[0])
    check("exactly one gl.Contract", len(re.findall(r"^class \w+\(gl\.Contract\):", text, re.M)) == 1)
    check("no payout or transfer logic",
          "emit_transfer" not in text and "gl.get_contract_at" not in text)


def secret_checks():
    pattern = re.compile(r"0x[0-9a-fA-F]{64}")
    words = ("private", "secret", "mnemonic", "passphrase")
    offenders = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        if path.suffix.lower() not in (".py", ".md", ".json", ".yml", ".yaml",
                                       ".txt", ".toml", ".cfg", ".ini", ""):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line in content.splitlines():
            if pattern.search(line) and any(w in line.lower() for w in words):
                offenders.append(str(path.relative_to(ROOT)))
                break
    check("no private keys in the tree", not offenders, ", ".join(offenders))
    env_files = [p.name for p in ROOT.glob(".env*") if p.is_file()]
    check("no .env files in the tree", not env_files, ", ".join(env_files))
    config = (ROOT / "gltest.config.yaml").read_text(encoding="utf-8")
    check("gltest config carries no interpolated secrets", "${" not in config)


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def fixture_checks():
    legit = load("legitimate_claims.json")
    adversarial = load("adversarial_claims.json")
    cases = legit["cases"] + adversarial["cases"]
    ids = [c["case_id"] for c in cases]
    check("case ids are unique", len(ids) == len(set(ids)))
    required = ("case_id", "title", "test_type", "attack_input",
                "expected_safety_property", "expected_outcome", "expected_property",
                "expected_indicators", "decided_by", "why_fail_closed", "claim",
                "panel", "live")
    missing_keys = [c["case_id"] for c in cases if any(k not in c for k in required)]
    check("every case names input, property, outcome and why it fails closed",
          not missing_keys, ", ".join(missing_keys))
    check("legitimate cases all expect VALID",
          all(c["expected_outcome"] == "VALID" for c in legit["cases"]))

    referenced = set()
    problems = []
    for c in cases:
        for e in c["claim"]["evidence"]:
            source = e.get("sha256_of", e["file"])
            referenced.add(source)
            if not (FIXTURES / source).exists():
                problems.append(c["case_id"] + ": " + source)
            if not (FIXTURES / e["file"]).exists() and "sha256_of" not in e:
                problems.append(c["case_id"] + ": missing " + e["file"])
            if not (FIXTURES / e["file"]).exists() and \
                    not e["file"].startswith("evidence/moved/"):
                problems.append(c["case_id"] + ": unreachable files live under evidence/moved/")
    check("every referenced fixture exists (unreachable ones under evidence/moved/)",
          not problems, "; ".join(problems))
    check("evidence/moved/ is empty (it stands for dead locations)",
          not (FIXTURES / "evidence" / "moved").exists()
          or not any((FIXTURES / "evidence" / "moved").iterdir()))

    docs = [p for p in FIXTURES.rglob("*") if p.is_file() and p.suffix in (".txt", ".json")
            and p.name not in ("legitimate_claims.json", "adversarial_claims.json")]
    big = [p.name for p in docs if p.stat().st_size > FETCH_BYTES_CAP]
    check("every evidence document fits the fetch cap", not big, ", ".join(big))
    cr = [p.name for p in docs if b"\r" in p.read_bytes()]
    check("evidence documents are LF-only (hashes survive checkouts)", not cr, ", ".join(cr))
    unused = [str(p.relative_to(FIXTURES)) for p in docs
              if str(p.relative_to(FIXTURES)).replace("\\", "/") not in referenced]
    check("every evidence document is used by a case", not unused, ", ".join(unused))

    structured_bad = []
    for p in docs:
        if p.suffix != ".json":
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        lines = sum(i["amount_minor"] for i in doc["line_items"])
        expected_mismatch = p.name == "estimate_altered.json"
        if p.name == "invoice_malformed.json":
            continue
        if (lines != doc["total_minor"]) != expected_mismatch:
            structured_bad.append(p.name)
    check("structured fixtures add up (except the altered estimate)",
          not structured_bad, ", ".join(structured_bad))

    bases = legit["panel_bases"]
    ungrounded = []
    for c in cases:
        spec = c["panel"]
        if spec is None:
            continue
        answer = {s: {} for s in ("criteria", "exclusions", "indicators")}
        if spec.get("base"):
            for s in answer:
                answer[s].update(bases[spec["base"]][s])
        for s in answer:
            answer[s].update(spec.get(s, {}))
        files = {"E" + str(i + 1): e["file"] for i, e in enumerate(c["claim"]["evidence"])}
        for section in answer.values():
            for subject, entry in section.items():
                for q in entry.get("quotes", []):
                    rel = files.get(q["evidence_id"])
                    if rel is None or not (FIXTURES / rel).exists():
                        continue   # quotes for documents absent from this case are
                                   # dropped by the contract, by design
                    if norm(q["text"]) not in norm((FIXTURES / rel).read_text(encoding="utf-8")):
                        ungrounded.append(f"{c['case_id']} {subject} {q['evidence_id']}")
    check("every recorded panel quote is verbatim in its document",
          not ungrounded, "; ".join(ungrounded))


def coverage_checks():
    tests = "\n".join(p.read_text(encoding="utf-8")
                      for p in (ROOT / "tests" / "direct").glob("test_*.py"))
    missing = [cat for cat, fn in CATEGORIES.items() if "def " + fn + "(" not in tests]
    check("all 20 brief attack categories have a named test", not missing,
          ", ".join(missing))


def address_checks():
    record = ROOT / "deploy" / "deployment.json"
    if not record.exists():
        check("deployment record (skipped: not deployed yet)", True)
        return
    deployment = json.loads(record.read_text(encoding="utf-8"))
    canonical = deployment["contract_address"].lower()
    allowed = {canonical} | {a.lower() for a in deployment.get("other_addresses", {}).values()}
    stray = []
    for path in [ROOT / "README.md", ROOT / "SUBMISSION.md"] + list((ROOT / "docs").glob("*.md")):
        if not path.exists():
            continue
        for address in re.findall(r"0x[0-9a-fA-F]{40}(?![0-9a-fA-F])", path.read_text(encoding="utf-8")):
            if address.lower() not in allowed:
                stray.append(f"{path.name}:{address}")
    placeholders = [p.name for p in [ROOT / "README.md", ROOT / "SUBMISSION.md"]
                    + list((ROOT / "docs").glob("*.md"))
                    if p.exists() and re.search(r"LIVE_SUMMARY|TO_BE_FILLED|TODO",
                                                p.read_text(encoding="utf-8"))]
    check("no unfilled placeholders in the docs", not placeholders,
          ", ".join(placeholders))
    check("docs name only the recorded addresses (one canonical deployment)",
          not stray, ", ".join(sorted(set(stray))))
    source = hashlib.sha256(CONTRACT.read_bytes()).hexdigest()
    check("deployment record names the current contract bytes",
          deployment.get("source_sha256") == source,
          f"record {deployment.get('source_sha256')} vs tree {source}")


def main():
    contract_checks()
    secret_checks()
    fixture_checks()
    coverage_checks()
    address_checks()
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS)} checks, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
