# Consensus

How one resolution round runs, what validators compare, and what they are
allowed to disagree on. Code references are by symbol in
`contracts/insureshield.py`.

## The validator task

A round is one `gl.vm.run_nondet_unsafe` call inside `InsureShield._run_round`,
reached from `resolve_claim` or `run_adversarial_test`. The leader and every
validator run the same procedure, `_node_round`, from their own vantage:

1. **Fetch and verify** each committed document with `gl.nondet.web.get`
   (`_fetch_row`). The raw bytes are hashed *before* anything reads them.
   A document is `EXAMINED` only when its bytes hash to the sha256 the
   claimant committed; otherwise it is `UNAVAILABLE` (no bytes, HTTP error),
   `HASH_MISMATCH` (different bytes), `TOO_LARGE` (over 12,000 bytes) or
   `UNPARSEABLE` (not UTF-8, empty, or a structured document that breaks the
   schema in `_structured_facts`).
2. **Read the hard facts in code.** For every examined `INVOICE` and
   `REPAIR_ESTIMATE`, `_structured_facts` reads document number, issuer,
   issue date, currency, total and the sum of its line items. For every
   examined document, `_injection_hits` scans for evaluator-directed phrases.
3. **Plan** (`_plan`): compute the five code indicators (`_code_indicators`),
   decide which criteria and exclusions code can decide (`_criterion_plan`,
   `_exclusion_plan`), which panel indicators apply (`_indicator_plan`), which
   documents each question may be answered from, and whether the panel is
   convened at all. The panel is skipped when any committed document was not
   examined (`EVIDENCE_NOT_EXAMINED`), when a hard fact is already present
   (`HARD_FACT_PRESENT`), or when nothing is left to ask
   (`NOTHING_TO_ASSESS`) - in each case no answer could change the verdict.
4. **Ask the panel once** (`PANEL_HEADER` + `_panel_blob`), with every
   examined document in full inside a JSON data block.
5. **Ground the answer** (`_panel_findings`): off-vocabulary states, foreign
   evidence ids and ungrounded quotes are discarded; a `SATISFIED` or
   `APPLIES` without a surviving quote, or a `PRESENT` that fails its quote
   rule, is downgraded to `UNVERIFIABLE` / `UNDETERMINED`.

The node returns a canonical JSON payload. It contains no verdict: the
verdict is derived after consensus, by `_derive`, from the agreed payload
and the duplicate registries.

## Evidence sources

Only documents the claimant committed, each as an `https` location plus the
sha256 of its exact bytes, fixed at `submit_claim` (or added or relocated,
never removed, at `retry_claim`). Nothing is searched for, and no node
chooses what to read. The policy owner may name `trusted_sources` (URL
prefixes) at policy creation; a criterion marked `trusted_only` may only be
answered from documents under those prefixes.

## Same-snapshot discipline

Hash binding makes the snapshot exact. Every node that examines a document
holds byte-identical content, so:

- the bytes a validator uses to classify are the bytes it uses to check the
  leader's quotes (`_validator_decision` passes its own texts to
  `_parse_payload`);
- a later round - a retry - reads the same bytes for every document that was
  already committed, and each receipt stores the evidence list and its
  `evidence_commitment`, so the record shows exactly what each round judged;
- a document whose served bytes change after commitment is `HASH_MISMATCH` -
  excluded before anything reads it, and never treated as fraud.

## Decision-critical fields (compared)

`_decision_fields_equal` is the equivalence rule. A validator ratifies only
when all of these equal its own:

| Field | Why it is compared |
|---|---|
| per row: `status`, `byte_count` | Reachability and exclusion decide `UNAVAILABLE` vs `INCONCLUSIVE`; a byte count exists only for verified bytes, which honest nodes hold identically. |
| `facts` (every field) | Totals and dates feed the hard-fact indicators; issuer and number feed the duplicate-document registry. |
| `markers` | Which document carries evaluator-directed text. |
| `panel_state`, `panel_reason` | A leader must not be able to claim the model failed (`MODEL_OUTPUT_INVALID` -> `INCONCLUSIVE`) when the validator's model answered. |
| every criterion, exclusion and indicator: `state` and `by` | Each one feeds `_derive`. |

Every field the verdict reads is therefore either compared here or computed
by deterministic code from compared fields (`_derive`, `_registry_findings`).

## Allowed differences (never compared)

- quotes, cited evidence ids and notes - two honest panels quote different
  passages and word things differently; instead, every quote is *grounded*
  (below);
- ordering and capitalisation of free text, whitespace inside quotes.

## Validator rejection conditions

`_validator_decision` returns `False` (disagree) when:

1. the leader result is not a `gl.vm.Return` and the error-vote table says
   so (`_vote_on_leader_error`: `[LLM_ERROR]` always disagrees; `[TRANSIENT]`
   agrees only if the validator's own run was transient too;
   `[EXPECTED]`/`[EXTERNAL]` only on the identical message);
2. the payload fails the structural gate `_parse_payload`:
   - not JSON, over 200,000 characters, or not exactly the documented keys;
   - a wrong `subject_id`, `round`, `definition_hash` or `evidence_commitment`;
   - a boolean or float where an integer is required, or an unknown enum;
   - a row that claims bytes it could not have (`UNAVAILABLE` with a byte
     count, `TOO_LARGE` under the cap);
   - facts for a document that was not examined, or missing for one that was;
   - markers naming a document that was not examined;
   - any code-decided finding that does not recompute from the payload's own
     rows, facts and markers;
   - a panel state or skip reason inconsistent with the plan;
   - an omitted or extra subject;
   - a panel finding citing an ineligible document, claiming `by: CODE`, or
     using a state outside its vocabulary;
   - a `SATISFIED` or `APPLIES` without a quote, or a `PRESENT` that fails its
     quote rule;
   - any quote whose words do not occur, contiguously and in order, in the
     validator's own verified bytes of the cited document (`_quote_grounded`);
3. any compared field differs from the validator's own reproduction.

A validator exception propagates and counts as disagreement.

## Grounding, not trust

A quote is the only content the leader authors that enters the permanent
record from the panel. It is corroborated where it enters the record: every
validator checks each one against bytes it fetched and hash-verified itself.
A leader cannot store a passage no other node saw, and cannot hide an empty
quote behind a positive finding (quotes are 8 to 240 characters and at
least two words).

The check compares words, not characters (`_word_tokens`): the quote's
lowercase alphanumeric words must appear in the document as one contiguous
run, or - when the quote elides with an ellipsis - as contiguous runs in the
same order. Punctuation, quote marks, dashes and line breaks are ignored.
This was changed after diagnostic rounds on a disposable StudioNet
deployment with a character-exact rule. Every validator split observed was
of one shape: a node running a different model family (Mistral, GLM, Qwen,
MiniMax) held `UNVERIFIABLE` or `UNDETERMINED` where the other nodes held
`SATISFIED` or `PRESENT` - the downgrade a node applies when none of its own
quotes pass grounding. In one round such a node led after rotation and the
round ended without a verdict. The diagnostics recorded the downgraded state,
not the quotes themselves; the character-exact rule was the one part of the
downgrade path that formatting alone could trip, so it was the part changed.
Word-level grounding tolerates formatting and still rejects anything the
document does not say - scattered words, reordered fragments, partial words
and paraphrase all fail (`test_quote_grounding_rule`). A node that downgrades
a finding prints `[DOWNGRADE] ...` to its own stdout, and a validator that
disagrees prints the first differing field as `[DISAGREE] ...`, so every
split in a live receipt can be read back.

## After consensus

The ratified text is parsed again at the boundary (`_run_round`); a payload
that fails the gate reverts the transaction with `[LLM_ERROR]` and nothing is
written. Then deterministic code runs the duplicate registries
(`_registry_findings`) and derives the verdict (`_derive`). Admission
rejections (`_admission_rejections`) are decided before any round and never
convene one.

## Protocol-level versus contract-level uncertainty

- **Protocol level:** a round whose validators do not reach agreement ends as
  the transaction's consensus outcome (rotations, then an undetermined
  result). Nothing is written; the claim stays `PENDING` and can be resolved
  again.
- **Contract level:** `INCONCLUSIVE` and `UNAVAILABLE` are agreed, recorded
  verdicts about the evidence. They are written in a receipt, leave the claim
  `RETRYABLE` (until the round limit) and are never consumable.

The two are never mapped onto each other. A transport failure of the model
itself raises `[TRANSIENT]` and reverts (protocol level); a model that
answered unusably is recorded as `MODEL_OUTPUT_INVALID` (contract level).
