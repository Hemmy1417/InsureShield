# Integration

How downstream contracts consume InsureShield. Every consumer below reads the
same receipt interface and asks the primitive the same question - does the
committed evidence satisfy this policy's criteria, and is there enough
verifiable evidence to say so - and then applies its own consequence.

## The interface a consumer needs

| View | Returns |
|---|---|
| `claim_outcome(claim_id, as_of)` | `status`, `verdict`, `severity`, `failure_class`, `confidence_band`, `freshness`, `consumable`, `duplicate_of`, `latest_receipt_id`, `policy_id`, `policy_version`, `definition_hash` |
| `is_consumable(claim_id, as_of)` | `true` only for a `RESOLVED` `VALID` claim whose receipt is `RELIABLE` as of `as_of`, whose version is not revoked and still carries the hash the claim was judged under, and which is not a later duplicate |
| `freshness(claim_id, as_of)` / `is_fresh` | `RELIABLE`, `STALE` (validity elapsed or version revoked), `BLOCKED` (latest verdict `UNAVAILABLE`), `UNKNOWN` |
| `get_receipt(receipt_id)` | the full record: evidence list and commitment, rows, facts, every finding with its deciding layer and quotes, verdict, reason codes, `evidence_digest`, `record_digest` |
| `definition_hash(policy_id, version)` | the hash a consumer pins to know which rules were applied |

`as_of` is the consumer's own clock. A view has no trustworthy clock of its
own, so a consuming contract passes its transaction datetime
(`gl.message_raw["datetime"]`) and an off-chain reader passes the current UTC
time. The result is an explicit state, never a timestamp to interpret.

A consumer should always check, in order: `found`; `policy_id` and
`definition_hash` against the policy it expects; then `consumable` (to act on
a positive outcome) or `verdict` (to act on an adverse one).

## Consumer 1 - an insurance claims workflow

The insurer's own claims contract routes each claim to an action.

```python
outcome = shield.view().claim_outcome(claim_id, gl.message_raw["datetime"])
if not outcome["found"] or outcome["definition_hash"] != EXPECTED_HASH:
    raise gl.vm.UserError("claim not assessed under the expected policy")
if outcome["consumable"]:
    route = "FAST_TRACK_PAYMENT"            # VALID, fresh, not a duplicate
elif outcome["verdict"] == "SUSPICIOUS":
    route = "SPECIAL_INVESTIGATIONS"        # read the receipt's indicators
elif outcome["verdict"] == "REJECTED":
    route = "DECLINE_WITH_REASONS"          # reason_codes name the exclusion
else:
    route = "ADJUSTER_REVIEW"               # INCONCLUSIVE / UNAVAILABLE
```

InsureShield never pays and never denies. `SUSPICIOUS` is a routing signal
for a human investigation, not an automatic permanent denial.

## Consumer 2 - a parametric insurance contract

A parametric cover pays a fixed amount when a trigger is met, and needs
evidence the loss occurred before it releases funds. It pins one policy
version whose criteria describe the trigger (for example, "the incident
report records flood water inside the insured premises on the claimed
date", `trusted_only` against a named authority's publication prefix) and
releases the fixed payout only on `is_consumable`.

```python
if not shield.view().is_consumable(claim_id, gl.message_raw["datetime"]):
    raise gl.vm.UserError("trigger evidence not established")
self._pay_fixed_amount(beneficiary)          # the consumer's own logic
```

The trust question is unchanged; the consequence is the consumer's.

## Consumer 3 - a dispute or appeal contract

An appeal contract lets a claimant contest a `REJECTED` or `INCONCLUSIVE`
outcome in front of human arbitrators or a second panel. It reads the
receipt, not a summary: which criterion or exclusion decided the outcome,
which layer decided it (`CODE`, `PANEL`, `REGISTRY`), the verbatim quotes the
panel relied on, and the `evidence_commitment` that fixes exactly which
bytes were judged.

```python
receipt = shield.view().get_receipt(outcome["latest_receipt_id"])
decisive = [f for f in receipt["exclusions"] if f["state"] == "APPLIES"]
# present decisive[i]["quotes"] and receipt["evidence"] to the arbitrators;
# the evidence digests let them fetch and verify the same bytes.
```

## Writing policy criteria

- Name the evidence kind a semantic criterion is judged from
  (`evidence_kind`). A criterion bound to a kind with no examined document is
  `UNVERIFIABLE` by code and never asked; leave it empty only for criteria
  that genuinely span every document.
- Write criteria as checks a reader can make against a document ("the
  incident report describes a collision involving the insured vehicle on the
  claimed date"), not judgments ("the claim is honest").
- Mark `trusted_only` any criterion the claimant must not be able to
  self-certify, and list the authority's URL prefix in `trusted_sources`.
- Mark `critical` the criteria whose failure should reject; a failed
  non-critical criterion makes the claim `INCONCLUSIVE` for review instead.
- Evaluate every rule change by replaying the recorded attacks and
  legitimate baselines onto the new version before adopting it
  (`docs/ADVERSARIAL_TESTING.md`).

## Structured documents

`INVOICE` and `REPAIR_ESTIMATE` documents are JSON the contract reads in code:

```json
{
  "document_type": "INVOICE",
  "document_number": "INV-20931",
  "issuer": "Eastfield Body Repairs Ltd",
  "issue_date": "2026-09-09",
  "currency": "USD",
  "line_items": [{"description": "Rear bumper cover - replaced and painted", "amount_minor": 128000}],
  "total_minor": 128000
}
```

Amounts are JSON integers in minor units. Other keys may be present and are
shown to the panel but not read by code. A document that breaks this schema
is `UNPARSEABLE` and the claim is `INCONCLUSIVE`. Because committed evidence
can never be removed, a claim carrying a malformed document stays
`INCONCLUSIVE` - a route to human review, not a denial. A claimant can
withdraw a claim before it is resolved and resubmit corrected evidence; once
a round has judged it, resubmitting its documents is flagged as a duplicate.
