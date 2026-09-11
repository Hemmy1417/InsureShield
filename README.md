<p align="center"><img src="https://raw.githubusercontent.com/Hemmy1417/InsureShield/main/docs/assets/insureshield-mark.svg" width="140" alt="InsureShield"/></p>

# InsureShield - Adversarial Insurance-Claims Evidence Verification

**A reusable GenLayer Intelligent Contract that decides, under validator consensus, whether committed claim evidence satisfies a versioned insurance policy - and treats the claimant's evidence as hostile.**

An insurer publishes a policy whose definition is frozen and hashed. A claimant commits a bounded list of evidence documents, each bound to the sha256 of its exact bytes. One consensus round has every validator re-fetch and hash-verify the documents; code decides every hard fact (arithmetic, amounts, dates, duplicates, injected instructions), a model panel decides only what needs reading, and every positive or adverse panel finding must carry quotes that each validator re-checks against the bytes it verified itself. The contract records a typed receipt - `VALID`, `SUSPICIOUS`, `INCONCLUSIVE`, `UNAVAILABLE` or `REJECTED` - that any downstream contract reads in one view, and it lets the insurer run recorded attacks against its own rules on-chain.

Canonical deployment: [`0x638f5610288d292Fac9DfdD53d094Da0c38c5299`](https://explorer-studio.genlayer.com/address/0x638f5610288d292Fac9DfdD53d094Da0c38c5299) on GenLayer StudioNet, byte-identical to `contracts/insureshield.py` at commit `aa01aa2` (see `docs/DEPLOYMENT.md`).

## At a glance

| Question | Answer |
|---|---|
| What is InsureShield | A standalone Intelligent Contract primitive: a claim-evidence verification and fraud-classification layer for insurance workflows. No frontend, no backend, no payouts. |
| What does it decide | Whether a claim's committed evidence satisfies its policy's criteria, whether an exclusion applies, whether the documents show fraud or manipulation, and whether there is enough verifiable evidence to say so at all. |
| Why GenLayer must decide it | Arithmetic and dates are code. Whether a police report "describes a collision involving the insured vehicle", whether a trip "was commercial use", or whether a photo log contradicts the repairs billed is reading. One model behind one backend is a single authority the claimant cannot challenge; GenLayer has independent validators read the same bytes and agree finding by finding. |
| What evidence it uses | Only documents the claimant committed: an `https` location and the sha256 of the exact bytes. Every node verifies the hash before anything reads a byte. The insurer can require specific criteria to be met only by documents from named authority prefixes. |
| How consensus works | `gl.vm.run_nondet_unsafe`, once per round. Each validator reproduces the whole round, gates the leader's payload against its own verified bytes, and agrees only if every row status, structured fact, injection marker, panel state and finding state matches. Prose is never compared; every stored quote is grounded. |
| How another contract consumes it | `claim_outcome(claim_id, as_of)` returns verdict, severity, freshness, consumability and the definition hash; `is_consumable` is the fail-closed shortcut; `get_receipt` is the full record. `docs/INTEGRATION.md`. |
| Where the canonical deployment is | StudioNet (chain 61999) `0x638f5610288d292Fac9DfdD53d094Da0c38c5299`, deploy tx `0xda9d6f05...1654` FINALIZED with 5/5 AGREE, source byte-identical. `docs/DEPLOYMENT.md`. |
| What tests prove it works | 341 Direct Mode tests on the official `genlayer-test` runner (lifecycle, every fixture case, the on-chain test engine, forged leaders through the captured validator closure, hostile model output, type confusion, URL admission, verdict precedence, concurrency); a mutation sweep on the deployed contract (109 killed, 1 documented equivalent); `genvm-lint check` ok with zero errors; 4 integration tests against the deployment; and a live run on it in which all 20 safety properties held with real models. See "Verified end-to-end". |

## What it is

- **Versioned, hashed policies** - a definition is strict JSON, stored canonically and covered by `definition_hash`; a new version never changes a claim already submitted, and a revoked version makes its claims unconsumable.
- **Hash-bound, append-only evidence** - up to six documents per claim; a retry may add or relocate a document (same bytes) but never remove one, so a finding cannot be erased by dropping the evidence that produced it.
- **Code decides the hard facts** - line-item arithmetic, claim versus invoice, invoice versus estimate, dates against the incident, duplicate documents across claims, and evaluator-directed text. Any one of them is `SUSPICIOUS` without a model being asked.
- **Consensus decides the reading** - semantic criteria, exclusions, and five manipulation or contradiction indicators, each answerable only from the documents the policy binds it to, each positive or adverse answer grounded in quotes every validator re-checks.
- **An adversarial-test engine** - the insurer registers attack cases against a policy version, anyone runs them through exactly the pipeline a real claim meets, and a rule change is evaluated by replaying the recorded attacks onto the new version.

## How it works

### For the insurer (policy owner)

1. `create_policy(definition_json)` - the caller becomes the owner; the definition is frozen and hashed.
2. `register_adversarial_test` with the attacks the rules must withstand and the legitimate cases they must not reject; anyone calls `run_adversarial_test`.
3. To change the rules, `publish_policy_version`, then `replay_adversarial_test` onto the new version and read which safety properties still hold before any claim depends on it.
4. `revoke_policy_version` withdraws a version; its claims stop being consumable.

### For the claimant

1. Publish each document at an immutable `https` location and compute the sha256 of its exact bytes.
2. `submit_claim` against the policy's active version with the evidence list; the claim binds that version and its hash.
3. Anyone calls `resolve_claim`. The claim is `RESOLVED` (`VALID`, `SUSPICIOUS`, `REJECTED`) or `RETRYABLE` (`INCONCLUSIVE`, `UNAVAILABLE`).
4. On `RETRYABLE`, after the policy's cooldown, `retry_claim` to relocate an unreachable document or add a missing one, then resolve again (at most three rounds).

### For a downstream contract

1. Read `claim_outcome(claim_id, as_of)` with your own transaction datetime.
2. Check `found`, `policy_id` and `definition_hash` against the policy you rely on.
3. Act on `consumable` for a positive outcome, or on `verdict` for routing (`SUSPICIOUS` to investigation, `REJECTED` to a reasoned decline, the rest to review).
4. For reasons, read `get_receipt(latest_receipt_id)`: every finding, its deciding layer and its quotes.

## Verdicts

| Verdict | Meaning | Consumable |
|---|---|---|
| `VALID` | Every document examined; every criterion satisfied with grounded quotes; no exclusion applies; no indicator present. | Yes, while fresh |
| `SUSPICIOUS` | A hard fact found by code (`CRITICAL`) or a manipulation indicator found by the panel (`HIGH`). A routing signal for investigation, never an automatic denial. | No |
| `INCONCLUSIVE` | Contradictory, malformed or insufficient evidence, or an unusable model answer. | No; retryable |
| `UNAVAILABLE` | A committed document could not be reached, or its bytes changed since commitment. Never treated as fraud. | No; retryable |
| `REJECTED` | An explicit policy condition failed: limit, coverage period, reporting window, an exclusion that applies, or a critical criterion unmet. | No |

Freshness is `RELIABLE`, `STALE` (validity elapsed or version revoked), `BLOCKED` (latest verdict `UNAVAILABLE`) or `UNKNOWN`.

## Lifecycle

```text
create_policy (insurer) ----> version 1 ACTIVE --publish_policy_version--> v1 SUPERSEDED, v2 ACTIVE
                                     |                                    (old claims stay bound to v1)
submit_claim (claimant)              v
        |                         PENDING --resolve_claim (anyone)--> RESOLVED  (VALID | SUSPICIOUS | REJECTED)
        |                            ^   \                             terminal
        |                            |    \--------------------------> RETRYABLE (INCONCLUSIVE | UNAVAILABLE)
        |                            |                                     |
        |                            +-------retry_claim (claimant, after cooldown; add or relocate only)
        |                                     after round 3 a RETRYABLE outcome is terminal
PENDING | RETRYABLE --cancel_claim (claimant)--> CANCELLED (terminal, never consumable)
```

| Status | Meaning |
|---|---|
| `PENDING` | Awaiting its next round. |
| `RETRYABLE` | Last round `INCONCLUSIVE` or `UNAVAILABLE`; the claimant may add or relocate evidence after the cooldown. |
| `RESOLVED` | Terminal verdict with its receipt. |
| `CANCELLED` | Withdrawn by the claimant; its evidence stays in the duplicate registry. |

A resolution is one atomic transaction, so there is no persistent "resolving" state.

## GenLayer consensus functions

| Function | Kind | What runs under consensus |
|---|---|---|
| `resolve_claim(claim_id)` | write, `gl.vm.run_nondet_unsafe` | Admission in code first (policy limit, coverage period, reporting window). Then per document `gl.nondet.web.get` and sha256 verification; structured facts and injection markers in code; one panel prompt only when its answer can change the verdict; grounding of every quote. Every validator reproduces it all and compares. |
| `run_adversarial_test(test_id)` | write, same round | The identical pipeline over a registered attack; registries are read, never written. |
| all other writes and views | deterministic | Validation, hashing, registries, transitions, bounded reads. |

## Contract

| Item | Value |
|---|---|
| Network | GenLayer StudioNet (chain id 61999) |
| RPC | `https://studio.genlayer.com/api` |
| Explorer | [explorer-studio.genlayer.com/address/0x638f...5299](https://explorer-studio.genlayer.com/address/0x638f5610288d292Fac9DfdD53d094Da0c38c5299) (code tab shows the deployed source) |
| Address | `0x638f5610288d292Fac9DfdD53d094Da0c38c5299` |
| Deploy tx | [`0xda9d6f05d38e1545e4d846d46829d5c229ea3df7de93f38c3312d06861901654`](https://explorer-studio.genlayer.com/tx/0xda9d6f05d38e1545e4d846d46829d5c229ea3df7de93f38c3312d06861901654) - FINALIZED, leader SUCCESS, 5/5 AGREE |
| Source | `contracts/insureshield.py`, runner `py-genlayer:1jb45aa8...` pinned; commit `aa01aa2`, blob `6486d8c`, sha256 `a0878565...497b` |
| Signer | `0x4CF07DDa95ecfC36ed1Ef7970F94c73BEB9cAdDf` |

### Write methods

| Method | Who | Payable | Notes |
|---|---|---|---|
| `create_policy(definition_json)` | anyone; caller becomes owner | no | Strict JSON definition, frozen and hashed; returns `POL-nnnnnn`. |
| `publish_policy_version(policy_id, definition_json)` | owner | no | New `ACTIVE` version; previous `SUPERSEDED`; at most 8. |
| `revoke_policy_version(policy_id, version)` | owner | no | Terminal; its claims stop being consumable. |
| `submit_claim(policy_id, claim_reference, claim_description, incident_date, claimed_amount, evidence_kinds, evidence_urls, evidence_hashes)` | anyone; caller becomes claimant | no | 1..6 hash-bound documents within the policy's bounds; one reference per claimant per policy. |
| `resolve_claim(claim_id)` | anyone | no | Admission, then one consensus round; one receipt per round. |
| `retry_claim(claim_id, evidence_kinds, evidence_urls, evidence_hashes)` | claimant | no | From `RETRYABLE` after the cooldown; add or relocate, never remove. |
| `cancel_claim(claim_id)` | claimant | no | From `PENDING` or `RETRYABLE`. |
| `register_adversarial_test(policy_id, version, test_type, attack_description, attack_payload, expected_property, expected_indicator)` | owner | no | A synthetic claim with the same admission rules; at most 24 per version. |
| `run_adversarial_test(test_id)` | anyone | no | Once; records the observed verdict and whether the property held. |
| `replay_adversarial_test(test_id, target_version)` | owner | no | The same attack against another version. |

### Read methods

`get_config`, `get_policy`, `definition_hash`, `get_claim`, `get_receipt`, `latest_verdict`, `claim_outcome`, `freshness`, `is_fresh`, `is_consumable`, `evidence_owner`, `get_adversarial_test`, `list_claims` and `list_adversarial_tests` (pages of at most 50), `get_stats`. Views return typed data and never revert on unknown ids.

### Consensus guarantees

- Compared exactly by every validator: each row's status and byte count, every structured fact, the injection markers, the panel state and skip reason, and the state and deciding layer of every criterion, exclusion and indicator. The verdict, severity, reason codes and digests are derived by code from those fields.
- A structural gate refuses a leader payload with a wrong key, a boolean or float where an integer belongs, an unknown enum, a code-decided finding that does not recompute, or a quote whose words are not in the validator's own verified bytes. The same gate runs again on the ratified text before anything is written.
- A validator that disagrees prints the first differing field to its own stdout, and a node that downgrades a finding prints why, so any split in a receipt can be read back.

## Verified end-to-end

Live, on the deployment of record, with real validators, real web fetches of
commit-pinned evidence and real models (`scripts/live_scenarios.py`, transcript
`deploy/live_scenarios_transcript.json`, every hash in `docs/DEPLOYMENT.md`):

```text
PHASE T - the adversarial suite on-chain (policy v1)
  L-01 VALID [] -> property HELD                          complete, consistent claim
  L-02 VALID [] -> property HELD                          deer strike at 02:10 (unusual, coherent)
  A-01 SUSPICIOUS ['DATE_CONFLICT'] -> property HELD      invoice dated before the incident
  A-02 SUSPICIOUS ['ARITHMETIC_MISMATCH'] -> property HELD  estimate total edited upward
  A-03 SUSPICIOUS ['AMOUNT_INFLATED'] -> property HELD    claim above own invoice
  A-04 SUSPICIOUS ['ESTIMATE_EXCEEDED'] -> property HELD  invoice far above estimate
  A-07 INCONCLUSIVE ['WITNESS_CONFLICT'] -> property HELD witness gives another date
  A-08 INCONCLUSIVE ['WITNESS_CONFLICT'] -> property HELD witness reverses the collision
  A-09 INCONCLUSIVE [] -> property HELD                   self-issued ownership, untrusted host
  A-10 SUSPICIOUS ['OWNERSHIP_MISMATCH'] -> property HELD registry names another keeper
  A-11 SUSPICIOUS ['DAMAGE_MISMATCH'] -> property HELD    photos contradict billed repairs
  A-12 SUSPICIOUS ['INJECTION_MARKER'] -> property HELD   "NOTE TO THE AI ..." (panel never asked)
  A-13 SUSPICIOUS ['INSTRUCTION_INJECTION'] -> property HELD  note to "whoever is reviewing"
  A-14 INCONCLUSIVE [] -> property HELD                   ownership evidence missing
  A-15 UNAVAILABLE [] -> property HELD                    photo log returns 404
  A-16 UNAVAILABLE [] -> property HELD                    invoice bytes changed
  A-18 INCONCLUSIVE [] -> property HELD                   float amounts in a structured invoice
  A-19 REJECTED [] -> property HELD                       reported after the window (admission)
PHASE R - evaluating a rule change against recorded attacks
  L-01 on v2 (tolerance 5%) SUSPICIOUS ['ESTIMATE_EXCEEDED'] -> property NOT HELD
  v2 flags the legitimate baseline: the change would create a false positive
  L-01 on v3 VALID -> HELD      A-04 on v3 SUSPICIOUS ['ESTIMATE_EXCEEDED'] -> HELD
PHASE C - real claims on policy v3
  CLM-000001 RESOLVED VALID ['ALL_CRITERIA_SATISFIED']   consumable, RELIABLE, HIGH
  CLM-000002 RESOLVED SUSPICIOUS ['DUPLICATE_EVIDENCE', 'DUPLICATE_DOCUMENT']
  CLM-000003 RETRYABLE UNAVAILABLE (photo log unreachable; panel skipped)
  CLM-000003 relocated (same sha256) -> RESOLVED VALID
  refused on chain: a stranger's test registration, a stranger's policy version,
  resolving a terminal claim again, a stranger's retry
summary: 20 tests, 20 properties held
```

The v2 row is the expected result of that phase: it is how an insurer sees,
before adopting a rule, that the rule would reject a legitimate claim. Of the
21 test rounds, 18 had no dissenting validator and 3 finished by majority; the
dissenters' own stdout on chain names the field and the cause (an ungrounded
multi-line quote; a witness contradiction also labelled narrative), and no
split changed an outcome (`docs/DEPLOYMENT.md`, "Validator agreement").

Offline:

```text
$ python scripts/preflight.py            27 checks, 0 failed
$ python -m pytest tests/direct -q       341 passed
$ python scripts/mutation_check.py       109 killed, 1 survived (documented equivalent; deploy/mutation_sweep_aa01aa2.txt)
$ genvm-lint check contracts/insureshield.py --json   {"ok":true, ... "methods":25}
$ INSURESHIELD_LIVE_WRITES=1 python -m pytest tests/integration -v   4 passed in 237.83s
```

## Tech stack

| Layer | Choice |
|---|---|
| Contract | Python on GenVM, runner `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6` |
| Consensus | `gl.vm.run_nondet_unsafe` with a custom validator |
| Tests | `genlayer-test` 0.29.2 Direct Mode, pytest 9.1.1, cloudpickle pickling checks |
| Lint | `genvm-linter` 0.11.0 (`genvm-lint check`) |
| Network tooling | `genlayer-py` 0.16.3 |

## Repository

```text
contracts/insureshield.py        the contract
tests/direct/                    Direct Mode suite (lifecycle, adversarial, hardening)
tests/integration/               attaches to the recorded deployment
fixtures/                        evidence documents and the case catalogue
scripts/preflight.py             structural gate (runner pin, fixtures, secrets, addresses)
scripts/mutation_check.py        mutation sweep with accept-control
scripts/deploy_studionet.py      deploy, verify parity, record
scripts/live_scenarios.py        the live run on the deployment of record
scripts/diagnostic_rounds.py     disposable diagnostic deployments
scripts/fetch_genvm_bundle.py    seeds the GenVM runner cache (CI, fresh clones)
deploy/                          deployment record, live transcript, diagnostics
docs/                            CONSENSUS, SECURITY, ADVERSARIAL_TESTING, INTEGRATION, DEPLOYMENT
DECISION.md, SUBMISSION.md
```

## Getting started

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-test.txt
python scripts/fetch_genvm_bundle.py
python scripts/preflight.py
python -m pytest tests/direct -q
genvm-lint check contracts/insureshield.py --json
```

Against the network (gasless; accounts are generated locally):

```bash
python scripts/deploy_studionet.py --verify
python -m pytest tests/integration -v                       # read-only checks
INSURESHIELD_LIVE_WRITES=1 python -m pytest tests/integration -v   # plus two write flows
python scripts/live_scenarios.py 0x638f5610288d292Fac9DfdD53d094Da0c38c5299 --raw-base https://raw.githubusercontent.com/Hemmy1417/InsureShield/aa01aa225467f074b9adbbb15151002d4e319a6c/fixtures/
```

## Security

- Every document is untrusted: evaluator-directed text is a hard fact found in code and never shown to a model; the rest reaches the model only as JSON data.
- Evidence is hash-bound before anything reads it; a changed document is excluded, not accused.
- URL admission rejects plain http, credentials, non-443 ports, IP literals, local and internal names, fragments, dot-segments and encoded separators - defence in depth; runtime egress controls remain the boundary.
- Authenticity is not proven by a hash; the insurer's trusted-source prefixes are the only corroboration class the contract recognises.
- Details: `docs/SECURITY.md`.

## Design notes

- The model is asked which criteria the evidence satisfies and what supports each; it is never asked whether to pay.
- The panel is convened only when its answer can change the verdict: never on a partial record, never once a hard fact is present.
- An adverse panel conclusion needs every committed document examined; only code-proven facts conclude on a partial record.
- Contradictions are `INCONCLUSIVE`, not `SUSPICIOUS`: an inconsistent account can be an honest mistake.
- Duplicate detection follows commitment order, never resolution order; a later duplicate resolved first stops being consumable once its original is examined.

## Disclaimer

InsureShield is a verification primitive, not an insurer, an adjuster or legal advice. A `VALID` verdict means the committed documents satisfy the policy's written criteria under the panel's reading; it does not prove the documents are genuine or the event occurred. Everything a claim commits is public on-chain. Use it as one input to a claims process that keeps a human decision for adverse outcomes.
