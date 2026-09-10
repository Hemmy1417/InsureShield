# Decision record

Why InsureShield, why this shape, and why it is a standalone Intelligent
Contract.

## The question it answers

> Does the submitted evidence satisfy the defined insurance-claim criteria,
> and is there enough independently verifiable evidence to classify the claim
> as valid, suspicious, inconclusive, unavailable or rejected?

## Portfolio collision analysis

Earlier builds by the same author that touch insurance or evidence
adjudication, and how InsureShield differs:

| Build | What it decides | Overlap | Why InsureShield is not a copy |
|---|---|---|---|
| Triggera | whether a parametric trigger (a measured reading) was met, then settles a payout | insurance vocabulary | Parametric: a number from publishers decides. InsureShield is indemnity claims: narrative and documentary evidence decides, and there is no payout. |
| ClaimSense | crop drought cover: plural weather sources against an index | insurance vocabulary | Parametric and index-based; no claimant documents, no fraud model. |
| Tradera | whether trade documents conform to a frozen specification | hash-bound documents, deterministic facts plus semantic criteria | The closest ancestry and the reason the evidence model is trusted. Tradera has no adversary inside the evidence: its documents are presumed honest and only checked for conformity. InsureShield assumes the claimant is the adversary, adds fraud indicators, duplicate registries across claims, injection defences, grounded quotes and an on-chain adversarial-test engine. |
| Adjudex, SignalCourt, Verda | disputes, signal courts, milestone verification | evidence dossiers, appeals | Different trust question; InsureShield has no bonds or appeals and moves no value. |

Reused deliberately, from builds that shipped and were reviewed: the pinned
StudioNet runner, hash-verification before any prompt (Tradera), "the model
returns findings, code derives the verdict" (Factora), grounding stored
excerpts against each validator's own bytes (S39, from the Triggera and
Verda letters), and the Direct Mode harness with validator replay.

## Ecosystem collision analysis

The GenLayer material reviewed for this build (the official contract-writing
skills and example contracts, including a prediction market) covers web
oracles, markets and escrow patterns; none of it is a reusable primitive for
adjudicating documentary claim evidence with an explicit fraud and
fail-closed model. This is a statement about what was reviewed, not a survey
of every GenLayer project. Off-chain AI claim-triage products are
single-authority by construction, which is the problem the brief states.

## Alternatives considered

| Idea | For | Against | Score /25 |
|---|---|---|---|
| Generic AI fraud score (0-100) | simple consumer interface | a score has no fields validators can meaningfully agree on; a single number invites an automatic denial; the brief rules out a "fraud-risk score marketed as truth" | 9 |
| Parametric flight-delay oracle | clean deterministic data | collides with Triggera; GenLayer barely load-bearing (one API reading) | 11 |
| Medical claims adjudication | high stakes, real problem | private data cannot be public on-chain; out of scope in the brief | 8 |
| Reinsurance treaty conformity | real, document-heavy | narrow audience; few consumers; no adversary model | 14 |
| **InsureShield: indemnity-claim evidence verification with adversarial testing** | documentary evidence needs judgment; fraud is adversarial by nature; typed receipts serve many consumers | panel agreement on narrative readings is the hardest risk (below) | **21** |

Scoring: problem reality (5), GenLayer load-bearing (5), reusability (5),
testability of the safety claims (5), collision risk (5).

## Why InsureShield was selected

The claimant controls the evidence. That makes the problem genuinely
adversarial, and it fixes the design: bind the evidence at submission,
decide every fact code can decide, ask the panel only what needs judgment,
make every adverse or positive panel finding carry verbatim support that
each validator re-checks, and make every failure mode land somewhere other
than `VALID`. The adversarial-test engine turns that into something an
insurer can measure against its own rules before a claim depends on them.

## Delete-GenLayer answer

Remove GenLayer and one of two things happens. Either one party - the
insurer, a vendor, a single model behind one API - becomes the authority
that reads the evidence, and a claimant or a downstream contract can only
trust or distrust it; or the rules are reduced to what a normal smart
contract can check, which is arithmetic and dates, and every contradiction,
exclusion, ownership mismatch and injected instruction goes unread.
GenLayer is load-bearing exactly where the brief puts it: independent
validators fetch the same committed bytes, read them, and must agree on each
decision-critical finding, while deterministic code bounds what that
agreement can change.

## Three-consumer proof

`docs/INTEGRATION.md` shows three consumers on one receipt interface, none
changing the trust question:

1. an insurer's claims workflow routing claims to payment, investigation,
   decline or adjuster review;
2. a parametric cover that releases a fixed payout only on a consumable
   `VALID` for trigger evidence from a named authority;
3. an appeal contract presenting the deciding findings, their layer and
   their verbatim quotes to arbitrators.

## Hardest technical risk

Validators must agree, state for state, on semantic findings produced by
independent model calls. A borderline reading - "does this exclusion
apply?" - can split validators and force rotations, or end undetermined.

Mitigations in the design: the panel is not convened when its answer cannot
change the verdict (a partial record, or a hard fact already found); code
decides every subject it can; each question names the only documents it may
be answered from; the vocabulary per subject is three states; silence is
defined as `UNVERIFIABLE`; contradictions need two documents; and only
states are compared, never prose. What remains is measured, not assumed:
the live run records each panel-decided case as held or not held.

## Why a standalone Intelligent Contract

The primitive has no product around it and needs none. Its entire value is
the typed receipt and the rules that produce it: a reusable decision layer
that claims systems, parametric covers and appeal processes consume without
reimplementing evidence binding, fraud checks or consensus. It holds no
funds, so its correctness does not depend on any consumer's economics, and
any consumer's consequence (pay, investigate, decline, appeal) stays in the
consumer.
