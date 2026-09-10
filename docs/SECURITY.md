# Security

Threats, the defence for each, and what the contract cannot prove. Code
references are by symbol in `contracts/insureshield.py`.

## Prompt injection and hostile evidence

Every fetched document is untrusted data written by an interested party.

- **Two layers.** `_injection_hits` scans every examined document, in code,
  for a conservative list of evaluator-directed phrases (`INJECTION_MARKERS`:
  "ignore previous instructions", "note to the AI", "mark this claim as
  valid", ...). A hit is the hard fact `INJECTION_MARKER`: the claim is
  `SUSPICIOUS` and the panel is never convened, so the injected text never
  reaches a model. Injection that avoids those phrases is the panel's
  `INSTRUCTION_INJECTION` question, which also makes the claim `SUSPICIOUS`.
- **Framing.** `PANEL_HEADER` states that everything in the data block is
  untrusted, that text addressed to the evaluator must never be followed,
  and that the claimant statement is a claim, not evidence.
- **No forgeable fences.** Documents, criteria and the claimant statement
  reach the prompt only as values inside one canonical JSON object
  (`_canonical`), so a document cannot close a fence or impersonate a
  contract-authored section.
- **The model cannot set the outcome.** It answers per-subject questions. It
  is never asked for a verdict, a payout or an amount; extra keys it returns
  (`"verdict": "VALID"`) are ignored; code-decided subjects are not asked and
  its answers for them are ignored.

## SSRF: defence in depth, not a guarantee

`_url_parts` admits a location only when it is `https`, carries no
credentials, names no port other than 443, is a fully qualified DNS name (no
IP literal of any spelling, no `localhost`, `.localhost`, `.local`,
`.internal`, `.home.arpa`, `.lan`), has no fragment, no backslash, no
encoded separator or dot, no dot-segment and no empty segment, and fits 300
characters. This is admission hygiene. A public DNS name can still resolve
to an internal address; the runtime's egress controls are the real
boundary, and the contract does not claim otherwise.

## Evidence integrity and source independence

- **Integrity.** Each document is bound to the sha256 of its exact bytes at
  submission. A document that changed is `HASH_MISMATCH`, excluded before
  anything reads it, and the claim is `UNAVAILABLE` - not accused.
- **Authenticity is a different question.** A hash proves a document has not
  changed since it was committed, never that the event it describes
  happened. The contract recognises one corroboration class: provenance
  under a `trusted_sources` prefix the insurer fixed when the policy was
  created. A criterion marked `trusted_only` can be satisfied only by a
  document from there; a claimant-hosted copy is not eligible and the
  criterion is `UNVERIFIABLE` by code. The claimant chooses the documents
  but cannot self-certify what the insurer requires from an authority.
- **Count is not corroboration.** The contract does not treat three
  documents as more reliable than one. Locations are deduplicated after
  canonicalisation (host case, port 443) and the same bytes cannot be
  committed twice, but independence between publishers is not inferred
  from URLs.

## Fraud signals the claimant cannot talk away

Hard facts are computed by code from hash-verified bytes and outrank
everything, including unreachable evidence:

| Indicator | Rule |
|---|---|
| `ARITHMETIC_MISMATCH` | a structured document's line items do not sum to its total |
| `AMOUNT_INFLATED` | the claim exceeds the invoices (or, with no invoice committed, the estimates) |
| `ESTIMATE_EXCEEDED` | the invoices exceed the estimates by more than the policy tolerance |
| `DATE_CONFLICT` | a structured document is dated before the incident or after submission |
| `INJECTION_MARKER` | evaluator-directed text in any document |
| `DUPLICATE_EVIDENCE` | a document's bytes were first committed by another claim |
| `DUPLICATE_DOCUMENT` | an invoice or estimate's issuer and number were first committed by another claim |

A comparison over a set of documents is made only when every committed
document of those kinds was examined (`_all_examined`); otherwise it is
`UNDETERMINED`. A sum over part of the record can be wrong in either
direction: this rule was added after the suite showed an excluded invoice
making `AMOUNT_INFLATED` fall back to the estimate.

## Duplicate registries

- **Bytes** (`evidence_registry`) are registered at commitment, first writer
  wins. An ownership record reused across claims on the same item is not a
  duplicate - unless it was first committed as another kind, so an invoice
  cannot be relabelled to escape. A claimant's own claim withdrawn before any
  round judged it does not count against them (a corrected resubmission);
  their own resolved claim does (double-dipping), and so does their own
  claim cancelled after a round - otherwise cancel-and-resubmit would
  launder away a recorded contradiction.
- **Document numbers** (`document_registry`) are only known once a document
  is examined. The registry keeps the earliest *commitment* carrying each
  key (`committed_seq`), so which claim is the duplicate follows commitment
  order, never the order in which claims happen to be resolved. A duplicate
  resolved before its original cannot be flagged at resolution; once the
  original is examined, `is_consumable` turns false for the later claim and
  `claim_outcome` names the original (`_later_duplicate_of`).
- Adversarial tests read both registries but never write them.

## Malformed model output

Handled in `_panel_findings` and `_normalize_answer`: a non-object answer or
a missing section is `MODEL_OUTPUT_INVALID` (`INCONCLUSIVE`,
`MODEL_OUTPUT`); an off-vocabulary state is undecided; notes are stripped of
control characters and cut to 200 characters; quotes outside 8-240
characters are dropped; at most three quotes are kept per finding.

## Replay prevention

- one `claim_reference` per claimant per policy (`reference_index`);
- one receipt per round, keyed `<claim>-R<n>`, refused if it exists;
- a claim is resolved only from `PENDING`; `VALID`, `SUSPICIOUS`, `REJECTED`
  and `CANCELLED` are terminal; retries are bounded (`MAX_ROUNDS` = 3) and
  cooled down (`retry_cooldown_seconds`);
- an adversarial test runs once.

## Policy versioning

A version's definition is stored as canonical JSON and covered by
`definition_hash` (policy id, version, owner, definition). Nothing can change
it. Publishing creates a new version; claims stay bound to the version and
hash they were submitted under and are always resolved under it. Revoking a
version makes its claims `STALE` and never consumable.

## Bounded state

Evidence per claim 6, rounds per claim 3, criteria 8, exclusions 4, trusted
sources 4, versions per policy 8, tests per version 24, claims per version
5,000, fetched bytes per document 12,000, URL 300, notes 200, quotes 3 x 240.
Views page with a limit of 50. The registries are keyed maps read by key,
never scanned.

## False-positive prevention

Rejecting everything is not safe either. The contract:

- decides only the hard facts in code and labels contradictions, which can be
  innocent, `INCONCLUSIVE` rather than `SUSPICIOUS`;
- tells the panel that unusual circumstances explained consistently are not
  contradictions, and that silence is `UNVERIFIABLE`, never `NOT_SATISFIED`;
- requires two documents and verbatim quotes for any contradiction;
- makes an indicator `NOT_APPLICABLE` when its evidence kinds are absent,
  so a minimal but sufficient claim is not held open;
- keeps legitimate cases (including an animal strike at 02:10) in the
  regression suite beside the attacks.

## Fail-closed behaviour

| Condition | Outcome |
|---|---|
| any document unreachable | `UNAVAILABLE` (only a code-proven hard fact outranks it) |
| a document changed since commitment | `UNAVAILABLE`, `EVIDENCE_CHANGED` |
| a document malformed or oversized | `INCONCLUSIVE` |
| the model's answer unusable | `INCONCLUSIVE`, `MODEL_OUTPUT` |
| a model call fails in transport | the transaction reverts; nothing written |
| validators disagree | nothing written; the claim stays `PENDING` |
| a panel conclusion on a partial record | impossible: the panel is not convened |
| `VALID` | only when every document is examined, every criterion `SATISFIED` with a quote, every exclusion `DOES_NOT_APPLY`, every indicator `ABSENT` or `NOT_APPLICABLE` |

## Privacy limitations

Everything a claim commits - URLs, the claimant's description, and every
document a validator fetches - is public on-chain and to every node. The
contract is not suitable for medical records or personal data that must stay
private. Hosts serving evidence should serve redacted documents.
