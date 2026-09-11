# Submission

InsureShield - adversarial insurance-claims evidence verification. A
standalone GenLayer Intelligent Contract. Every fact below was produced by a
command or read from the network; where a fact is observational rather than
asserted, it says so.

## Repository

| Item | Value |
|---|---|
| Repository | https://github.com/Hemmy1417/InsureShield |
| Contract path | `contracts/insureshield.py` |
| Canonical source commit | `aa01aa225467f074b9adbbb15151002d4e319a6c` (the contract is unchanged in every later commit) |
| Source blob | `6486d8ca0c5e4cc6ca5cf3b54da93ce9347a0f63` |
| Source sha256 | `a0878565b63f72433dcba3819509e3318219dc64ab145aac18a40796ee29497b` |
| Runner | `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6` (pinned) |

## Deployment

| Item | Value |
|---|---|
| Network | GenLayer StudioNet, chain id 61999, `https://studio.genlayer.com/api` |
| Contract address | `0x638f5610288d292Fac9DfdD53d094Da0c38c5299` |
| Explorer | https://explorer-studio.genlayer.com/address/0x638f5610288d292Fac9DfdD53d094Da0c38c5299 (the Code tab shows the deployed source) |
| Deployment transaction | `0xda9d6f05d38e1545e4d846d46829d5c229ea3df7de93f38c3312d06861901654` - https://explorer-studio.genlayer.com/tx/0xda9d6f05d38e1545e4d846d46829d5c229ea3df7de93f38c3312d06861901654 |
| Transaction status | `FINALIZED`; leader execution `SUCCESS`; validator votes `AGREE` x5 (read from the receipt) |
| Signer public address | `0x4CF07DDa95ecfC36ed1Ef7970F94c73BEB9cAdDf` |
| Source parity | the deployed source read back with `gen_getContractCode` has sha256 `a0878565...497b`, identical to the committed file; re-check with `python scripts/deploy_studionet.py --verify` or `tests/integration` |

## Validation and tests (actual results)

| Command | Result |
|---|---|
| `genvm-lint check contracts/insureshield.py --json` | `ok: true`; lint 3 passed; validate ok, 25 methods (15 view, 10 write); 0 errors; 1 informational warning (I200: a newer runner exists - that runner is a different SDK generation the linter itself cannot load) |
| `python scripts/preflight.py` | 27 checks, 0 failed |
| `python -m pytest tests/direct -q` | 341 collected, 341 passed, 0 failed, 0 skipped, about 44 s; Python 3.12.2, genlayer-test 0.29.2, pickling checks on for every test |
| `python scripts/mutation_check.py` (on the deployed contract) | 110 mutants: 109 killed, 1 survived; the survivor is an equivalent mutant (a redundant eligibility check) documented in the script; record `deploy/mutation_sweep_aa01aa2.txt` |
| `INSURESHIELD_LIVE_WRITES=1 python -m pytest tests/integration -v` (against the deployment) | 4 passed in 237.83 s (without the variable, as in CI: the 3 read-only checks) |
| clean clone of `dfea418`, fresh virtualenv from `requirements-test.txt` | preflight 27/0, 341 direct passed, `genvm-lint check` ok, integration 3 passed 1 skipped, no untracked files (`docs/DEPLOYMENT.md`) |
| CI (GitHub Actions, ubuntu) | required job green on every push: preflight, runner-bundle fetch, Direct Mode, `genvm-lint check` |
| `python scripts/live_scenarios.py` (on the deployment) | 20 on-chain adversarial tests, 20 safety properties held with real models; rule-change evaluation behaved as asserted; 3 real claims resolved as asserted; 4 refusals |

## What the live run shows

- Code-decided attacks (fabricated invoice, altered estimate, inflated claim,
  estimate overrun, explicit injection, missing evidence, untrusted ownership
  proof, unreachable source, changed bytes, malformed invoice, late notice):
  every expected outcome, asserted.
- Panel-decided cases (two legitimate claims including an unusual one;
  conflicting witness statements twice; an ownership record naming another
  keeper; photos contradicting the billed repairs; an injection phrased to
  avoid the marker list): every expected outcome, recorded. This is what the
  models answered on this run, not a guarantee they always will.
- A tighter rule replayed onto the legitimate baseline made it `SUSPICIOUS`
  (the false positive the phase exists to reveal); restored rules made it
  `VALID` again while still catching the overrun.
- A duplicate claim was caught by the registry; an unreachable document left
  a claim `UNAVAILABLE` and `RETRYABLE`, and relocating it made the claim
  `VALID`.
- 18 of the 21 test rounds had no dissenting validator; 3 finished by
  majority, and the dissenters' own stdout on chain names the cause.

## Known limitations

- A hash proves a document has not changed since commitment, not that it is
  genuine. The only corroboration class is the insurer's trusted-source URL
  prefixes.
- URL admission is defence in depth; runtime egress controls are the real
  SSRF boundary.
- Everything a claim commits is public on-chain; not for private or medical
  records.
- A duplicate invoice resolved before its original cannot be flagged at
  resolution; it becomes unconsumable, naming the original, once the original
  is examined.
- A claim carrying a malformed document stays `INCONCLUSIVE` (evidence is
  never removed); it routes to human review.
- Freshness views take the caller's clock (`as_of`); a view has no clock of its
  own.
- Semantic findings depend on validator models. The observed minority splits
  have two named causes (a quote joining non-adjacent lines; one inconsistency
  given two labels) and two recorded follow-ups, not applied because they
  require a new deployment (`docs/DEPLOYMENT.md`).
- The live run's phase C was interrupted by a StudioNet RPC outage and resumed;
  the records of its first steps were rebuilt from the chain's transaction
  history, as the transcript states.
- genlayer-test 0.29.2 needs two documented test-harness shims (Windows temp
  file unlinking; mid-test clock changes reaching `gl.message_raw`); both live
  in `tests/direct`, neither touches the contract.

## Documents

`README.md`, `DECISION.md`, `docs/CONSENSUS.md`, `docs/SECURITY.md`,
`docs/ADVERSARIAL_TESTING.md`, `docs/INTEGRATION.md`, `docs/DEPLOYMENT.md`.
