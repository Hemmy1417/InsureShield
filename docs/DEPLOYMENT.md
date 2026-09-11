# Deployment

The canonical deployment, the evidence that it matches this repository, the
live run on it, and every disposable deployment made on the way. Every hash
and address below can be opened at
`https://explorer-studio.genlayer.com/tx/<hash>` or `/address/<address>`;
the machine-readable record is `deploy/deployment.json` and the live
transcript is `deploy/live_scenarios_transcript.json`.

## Canonical deployment

| Item | Value |
|---|---|
| Network | GenLayer StudioNet, chain id 61999, RPC `https://studio.genlayer.com/api` |
| Contract | [`0x638f5610288d292Fac9DfdD53d094Da0c38c5299`](https://explorer-studio.genlayer.com/address/0x638f5610288d292Fac9DfdD53d094Da0c38c5299) |
| Deploy tx | [`0xda9d6f05d38e1545e4d846d46829d5c229ea3df7de93f38c3312d06861901654`](https://explorer-studio.genlayer.com/tx/0xda9d6f05d38e1545e4d846d46829d5c229ea3df7de93f38c3312d06861901654) |
| Receipt | status `FINALIZED`, leader execution `SUCCESS`, votes `AGREE` x5 |
| Signer | `0x4CF07DDa95ecfC36ed1Ef7970F94c73BEB9cAdDf` (key held outside the repository) |
| Deployed at | 2026-09-11T00:56:52Z |
| Source commit | `aa01aa225467f074b9adbbb15151002d4e319a6c` (the contract is unchanged in every later commit) |
| Source blob | `6486d8ca0c5e4cc6ca5cf3b54da93ce9347a0f63` |
| Source sha256 | `a0878565b63f72433dcba3819509e3318219dc64ab145aac18a40796ee29497b` |
| Runner | `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6` |

## Source parity

The deployed source was read back from the network with `gen_getContractCode`
(base64 of the stored bytes) and its sha256 equals the committed file's:
`a0878565b63f72433dcba3819509e3318219dc64ab145aac18a40796ee29497b` on both
sides. Three independent ways to re-check it:

- `python scripts/deploy_studionet.py --verify` - recomputes both hashes;
- `python -m pytest tests/integration -v` - `test_deployed_source_is_byte_identical`
  and `test_deployed_schema_exposes_the_public_interface` (25 methods);
- the explorer's contract page, Code tab, which shows the deployed source
  (15 read and 10 write methods).

## GenVM validation

```text
$ genvm-lint check contracts/insureshield.py --json
{"ok":true,"lint":{"ok":true,"passed":3},"validate":{"ok":true,"contract":"InsureShield",
 "methods":25,"view_methods":15,"write_methods":10,"ctor_params":0,
 "warnings":[{"code":"I200","msg":"py-genlayer: a newer runner is available (1zr6nqk...)"}]}}
```

`ok: true`, zero errors. I200 is informational. The newer runner it names
(`1zr6nqk...`) belongs to a different SDK generation: the same linter cannot
load it (`E101 Failed to load SDK: No module named 'genlayer.py'`), so the
pinned runner is the one current GenVM validation passes and the one
StudioNet runs.

## Live run on the deployment of record

`scripts/live_scenarios.py`, evidence pinned to
`https://raw.githubusercontent.com/Hemmy1417/InsureShield/aa01aa225467f074b9adbbb15151002d4e319a6c/fixtures/`.
Before any write the driver fetched every evidence URL and checked that it
serves exactly the committed bytes (24 files), and that the one location
standing for a dead link returns 404. Driver accounts (ephemeral; StudioNet is
gasless):

| Role | Address |
|---|---|
| insurer | `0xD65227b44f24099AF4758F0B89d6AA7904021A4b` |
| claimant | `0xd70f1b2C854c59FAC169a48Fb1C4C498317F729F` |
| second claimant | `0x01616e67A18386118c11861A1bb9a229987423B8` |
| stranger | `0xC19769fae025bDb860689861B87C18Ed611443CE` |

What the driver asserts (the run fails without it): every transaction's
leader execution result, every code-, registry- and admission-decided
outcome, every refusal, and the rule-change result. Panel-decided outcomes
are recorded and reported case by case; every one of them held.

### Phase T - the adversarial suite, policy `POL-000001` v1

Every live fixture case registered as an on-chain test by the insurer and run
by the stranger. `passed` is the contract's own record of whether the safety
property held.

| Case | Test | Observed | Indicators | Held | Decided by | Run tx |
|---|---|---|---|---|---|---|
| L-01 | AT-000001 | VALID | - | yes | panel | `0x393d77d2cdc14f7a16568a733316bf079ee6ebfe2a9a7ecea848e2c049d7efce` |
| L-02 | AT-000002 | VALID | - | yes | panel | `0x7ab59e149610584cb8800cfa75f3c2dba90d9ff2a8a6a9ee794d6fb2f2d9da14` |
| A-01 | AT-000003 | SUSPICIOUS | DATE_CONFLICT | yes | code | `0x4f8a9562961172197fb303c80d741e02b5a17fa89566b0326f2fce25efc39d67` |
| A-02 | AT-000004 | SUSPICIOUS | ARITHMETIC_MISMATCH | yes | code | `0x3267787a3b2c0eaf254957e99f24a7b29ba3bb00aaef8c667c6862f9578930a3` |
| A-03 | AT-000005 | SUSPICIOUS | AMOUNT_INFLATED | yes | code | `0xcaced9442d4934432bbc55d58e059b2632b120690a56454e8feaa284058d9917` |
| A-04 | AT-000006 | SUSPICIOUS | ESTIMATE_EXCEEDED | yes | code | `0xc55e89fc9086482ecf4efb444a4acb8907596652e65e1f04b2c881a9fc0538de` |
| A-07 | AT-000007 | INCONCLUSIVE | WITNESS_CONFLICT | yes | panel | `0xa2bdb8c99a9e09fbaf330a1fc56588bcc4404d8c6b099f521fa7c973e1bbc87f` |
| A-08 | AT-000008 | INCONCLUSIVE | WITNESS_CONFLICT | yes | panel | `0xfddd249d2dbb302f7684761a72be2d1ba03d6d6dec5ce02f5d831edaf7d72649` |
| A-09 | AT-000009 | INCONCLUSIVE | - | yes | code | `0xcf8932fa20faf1e6e90b92b7bf07391a98abe7dd7e8f0a43d9836469c02d69a2` |
| A-10 | AT-000010 | SUSPICIOUS | OWNERSHIP_MISMATCH | yes | panel | `0x6efcd62bc2bfc6fc14578f92573e4a39ed7d3b333cb5b1577868226e64a79949` |
| A-11 | AT-000011 | SUSPICIOUS | DAMAGE_MISMATCH | yes | panel | `0x75de0be37b105e42db486a68b5e8010f5f673f7d37a96ec0467201d182429b98` |
| A-12 | AT-000012 | SUSPICIOUS | INJECTION_MARKER | yes | code | `0x02019f2ece1ff72ecb5e62925bdc85ce32e1682c637aadc89aadc28259d028cf` |
| A-13 | AT-000013 | SUSPICIOUS | INSTRUCTION_INJECTION | yes | panel | `0x0562a450065689b44e7455b15d352d75e6c0ef4d4f2aeeb333e10b7e15a09ce5` |
| A-14 | AT-000014 | INCONCLUSIVE | - | yes | code | `0xd3039d79612d66cabe8b505a0d1cd1d0b3580a68c009bd3579754f1b0693a68f` |
| A-15 | AT-000015 | UNAVAILABLE | - | yes | code | `0x943a0a40c202c5969cedf6044d2d3de868d34285fbca62e138c574551ed01c64` |
| A-16 | AT-000016 | UNAVAILABLE | - | yes | code | `0x62b7403f745032f9019c82097353b2cb55e1bb38d23128fd3dc375551a58ccc7` |
| A-18 | AT-000017 | INCONCLUSIVE | - | yes | code | `0x864c59e6334ddecd25c47335a8ef4699151093f2709d08b6362331a2a2731c5f` |
| A-19 | AT-000018 | REJECTED | - | yes | admission | `0xa663fa73c9486a6074b12e1b9bc445a4247c58d80ec76f00250172c6da8856e0` |

Votes and receipt summaries for every row are in the transcript.
A-05 and A-06 (duplicates of a prior claim) and A-17 and A-20 are Direct Mode
only (A-05's behaviour is shown live in phase C); the legitimate L-03 is
Direct Mode only.

Refused, as designed: the stranger registering a test on the insurer's policy
(`0x38903d3ab171f4b843be85d271009257707f19c64ad6a1a1d405f5445ce5d4fd`, leader
`ERROR`, 5/5 agree).

### Phase R - evaluating a rule change

| Step | Result | Tx |
|---|---|---|
| stranger publishes a version | refused (`ERROR`) | `0xde9a054b5970c7c7a4aa3455f2acde368dcf22f25a7f9fe23ef77998c8951afe` |
| insurer publishes v2: estimate tolerance 15% -> 5% | `SUCCESS` | `0xf288306e4bd02a7ff56d1459b3a815ddcedbd9da9c8247c8410dd293c9fa89b8` |
| L-01 replayed onto v2 (AT-000019) | SUSPICIOUS, ESTIMATE_EXCEEDED - property **not held**: the proposed rule turns the legitimate 6.4% overrun into a fraud flag | `0x59dafe82672022d86abbb01679e8da3197c62e62eb48eac850189e3c1e4661fc` |
| insurer publishes v3: 15% restored | `SUCCESS` | `0x50ce0ab3ab2c10d3b76695741e297f3b80d0f8a0d17838d900d62db888a3b7e8` |
| L-01 replayed onto v3 (AT-000020) | VALID - held | `0xfe3b1bf1364e8cc321ee8f85f929908cd7a914061f7a3e04e8d602c2aa381380` |
| A-04 replayed onto v3 (AT-000021) | SUSPICIOUS, ESTIMATE_EXCEEDED - held | `0x77d5ef9693c482d42d072b9984cba31aff0d58260d984d3077742f5c3fcf3735` |

The v2 result is the point of the phase and is asserted by the driver: an
insurer sees on-chain, before adopting a rule, that it would reject a
legitimate claim.

### Phase C - real claims on v3

| Step | Result | Tx |
|---|---|---|
| claimant submits the complete legitimate claim | `CLM-000001` | `0x64d1d1ce7da85b76c06806dc630f05776ffc771fd00d8b7ac734ec8814bf93b4` |
| stranger resolves it | VALID, `ALL_CRITERIA_SATISFIED` | `0x49af8b65a5c256a9f7d0c1ce9a5d2bae03c82b6643df88ca7d4a82f527ca3cc5` |
| `claim_outcome` | consumable `true`, freshness `RELIABLE`, confidence `HIGH`, policy v3, definition hash `cf818066...bbc6` | (view) |
| stranger resolves it again | refused (`ERROR`) - terminal | `0x9edd62fb6add268a52869c0e4a08f4e8887ce7b129291e71b5685133569005b0` |
| second claimant submits the same documents | `CLM-000002` | `0x63d0cdbe3c923f492922eab7078c9a5fb7ffd892f0744eaade0bdd4b1d0ab107` |
| stranger resolves it | SUSPICIOUS: DUPLICATE_EVIDENCE, DUPLICATE_DOCUMENT (asserted) | `0x46bd5db57f313b0e2d8e4916308fd48d12ec2d280420762c7ad132acc64ff96f` |
| claimant submits the deer-strike claim with the photo log at a dead location | `CLM-000003` | `0xfd9d9be894815b9a3280e82be5f0c24724f592347c27ce3062da1b23efbeeafc` |
| stranger resolves it (round 1) | UNAVAILABLE, RETRYABLE, panel skipped (asserted) | `0x8f2219302f7aedd4fa9a7a256484ea628e471d43fc0159491e431f01b09cac91` |
| second claimant tries to retry it | refused (`ERROR`) | `0x3f8ba824f2cfe8c416b253af72d9be0e71cb67561cc01ecb6a0619355c38a97f` |
| claimant relocates the photo log (same sha256) | `SUCCESS` | `0xecf714bc893abe8d051a1b7993801858a7703d960643521452b9baba8922bbd3` |
| stranger resolves it (round 2) | VALID, `ALL_CRITERIA_SATISFIED`; the ownership record reused from `CLM-000001` is not a duplicate | `0x1d14e53a99ac357d4af52a2b970dc572a452d3d8ce2ddde2f6ed5f4b97ec2668` |

**Interruption.** The first run of phase C stopped just before the relocation
retry: the StudioNet RPC refused connections for several minutes (connect
timeouts on `eth_getTransactionCount`, beyond eight transport retries), so
that transaction was never sent. The run was resumed with
`--only C --recover`, which rebuilt the records of the steps already on chain
from the network's transaction history (`sim_getTransactionsForAddress`,
calldata decoded) and the contract's views - not from the log - and then sent
the two remaining transactions. The transcript marks phase C
`recovered_from_chain`. The driver now saves after every step.

### Validator agreement

Across the 21 test rounds, 18 had no disagreeing validator and 3 finished by
majority with a minority dissent. The dissenting nodes' own stdout, read back
from the chain (`deploy/live_validator_splits.json`):

| Round | Dissent | Cause |
|---|---|---|
| L-01 v1 (`0x393d77d2cdc14f7a16568a733316bf079ee6ebfe2a9a7ecea848e2c049d7efce`) | one node: C4 `UNVERIFIABLE` vs `SATISFIED` | its model quoted the ownership record as `VIN...\nMake / model...\nRegistered keeper...`, joining three lines that are not adjacent in the document; the quote was not grounded and the finding was downgraded |
| A-07 (`0xa2bdb8c99a9e09fbaf330a1fc56588bcc4404d8c6b099f521fa7c973e1bbc87f`) | two nodes: NARRATIVE_CONTRADICTION `PRESENT` vs `ABSENT` | their models also labelled the witness contradiction as a narrative contradiction, which the questions assign to WITNESS_CONFLICT |
| A-08 (`0xfddd249d2dbb302f7684761a72be2d1ba03d6d6dec5ce02f5d831edaf7d72649`) | one node the same; one node C3 `UNVERIFIABLE` vs `SATISFIED` | as above; and an ungrounded quote |

No split changed an outcome. Two changes would remove these specific causes
and are recorded as follow-ups rather than applied, because applying them means
replacing a verified deployment: accept quotes whose newline-separated lines
each ground in order (as ellipsis fragments already do), and compare the two
contradiction indicators as one class. Both would need a new deployment and a
new live run.

## Integration run

`INSURESHIELD_LIVE_WRITES=1 python -m pytest tests/integration -v` against the canonical deployment:
4 passed in 237.83 s (byte-identical source; the 25-method schema; the
deployed configuration; a policy, a late claim `REJECTED` at admission with no
fetch, and the fabricated-invoice attack registered and run as an on-chain
test, decided `SUSPICIOUS` by code with all six documents fetched and
hash-verified by every node). It created its own policy on the canonical
deployment with a fresh account. Without `INSURESHIELD_LIVE_WRITES=1` (as in CI) only the three read-only checks run.

## Clean-clone reproducibility

A fresh clone of `dfea418` into a new directory, with a fresh virtualenv
holding only the pins in `requirements-test.txt` installed from PyPI (so no
locally patched package can take part):

```text
python scripts/fetch_genvm_bundle.py      genvm bundle v0.3.0-rc7 cached and complete
python scripts/preflight.py               27 checks, 0 failed
python -m pytest tests/direct -q          341 passed in 57.22s
genvm-lint check contracts/insureshield.py --json   {"ok":true, ... "methods":25 ...}
python -m pytest tests/integration -q     3 passed, 1 skipped (writes are opt-in)
git status --short --ignored              only __pycache__ directories
```

The GenVM runner bundle was already cached on that machine; the cold-cache
path (download, verify, seed both caches) runs on every CI job, on a fresh
Ubuntu runner, and passes.

## Disposable deployments

Kept separate from the canonical one and never referenced as it:

| Address | Source | Purpose | Result |
|---|---|---|---|
| `0xe2364ea8249d8a349c0103FcA0dF132108932dFd` | `41ffdc5` | smoke test: deploy, read back, one real round | deploy `FINALIZED`/`SUCCESS`, source byte-identical; L-01 resolved VALID with a 3-2 vote |
| `0xA5128d12983a0517936536B43041B811af0174A3` | `41ffdc5` + validator diagnostics | diagnostic run 1: which field splits validators? | 6 of 7 rounds held; every split was a node downgrading a shared finding for lack of a grounded quote; one round ended without a verdict |
| `0xee892d1CeF312d92116d1b0D96BF56cCb2218ab6` | `4f245c2` (word-level grounding) | diagnostic run 2 | 6 of 6 held; remaining splits: downgrades and one label overlap |
| `0xecB86fE91c1BE0CDC505900755a289f83FdD0017` | `a898772` (quote shapes, answer envelopes, partitioned questions) | diagnostic run 3 | 5 of 5 held |

The diagnostic runs are why the grounding rule compares words rather than
characters, why quotes are accepted in the shapes models return, and why a
missing answer section leaves only its own subjects undecided
(`docs/CONSENSUS.md`, "Grounding, not trust"). Logs:
`deploy/diagnostics/`; the script: `scripts/diagnostic_rounds.py`.

## Reproduce

```bash
python scripts/deploy_studionet.py --verify
python -m pytest tests/integration -v
python scripts/live_scenarios.py 0x638f5610288d292Fac9DfdD53d094Da0c38c5299 \
  --raw-base https://raw.githubusercontent.com/Hemmy1417/InsureShield/aa01aa225467f074b9adbbb15151002d4e319a6c/fixtures/
```

A new live run on the same deployment creates a new policy and new claims; the
duplicate registry remembers the documents committed by `CLM-000001` to
`CLM-000003`, so a replay of phase C from fresh accounts would, correctly, see
its legitimate claim flagged as a duplicate of `CLM-000001`.
