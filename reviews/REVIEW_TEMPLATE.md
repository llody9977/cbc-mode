# Review record: <scope>

> Lives at `reviews/LATEST_REVIEW.md` and is overwritten by each new review — this file always holds the
> most recent one. Earlier records are in git, not in this folder:
> `git log -p --follow reviews/LATEST_REVIEW.md` for the full series,
> `git show <commit>:reviews/LATEST_REVIEW.md` for one in full.
>
> The machine-readable pass state lives beside it in `reviews/REVIEW_STATE.json`, written by
> `scripts/review_passes.py --record`. That file is the router's input; this one is the human record.

## Status and baseline

- Status: In progress | Complete with findings | Complete with no open findings
- Review date:
- Reviewer:
- Model / effort this review: `<model-id>` / `<low|medium|high|xhigh|max>`
- Branch:
- Commit:
- Worktree: Clean | Dirty (list every in-scope change below)
- Review state ID:
- State-capture command:
- Pass-routing command: `python3 scripts/review_passes.py --model <id> --effort <level>`
- Pass state recorded with: `--record '{"<pass-id>":"clean|findings", ...}'` (only passes that actually ran)
- Baseline changed during review: No | Yes (identify the new baseline and repeated passes)

### Prior review this one builds on

- Prior review date / model / effort:
- Prior commit:
- Passes carried forward from it:

## Scope inventory

| Artifact | Type | Direct dependents or generated counterpart | Inspected |
| --- | --- | --- | --- |
|  |  |  | No |

Out-of-scope boundaries and reason:

## Review passes

Copy the router's decision verbatim. A **cached** pass is carried forward on its own recorded
evidence — it was not verified by this review, and must never be described as if it were.

| id | Ver | Ran or cached | Reason (router's words) | Verdict | Evidence, or the run it rests on |
| --- | --- | --- | --- | --- | --- |
| `factual-correctness` |  | run \| cached |  | clean \| findings |  |
| `evidence-authority` |  | run \| cached |  | clean \| findings |  |
| `adversarial-claims` |  | run \| cached |  | clean \| findings |  |
| `terminology-taxonomy` |  | run \| cached |  | clean \| findings |  |
| `cross-format` |  | run \| cached |  | clean \| findings |  |
| `visual-content` |  | run \| cached |  | clean \| findings |  |
| `cross-page` |  | run \| cached |  | clean \| findings |  |
| `topic-completeness` |  | run \| cached |  | clean \| findings |  |
| `argument-integrity` |  | run \| cached |  | clean \| findings |  |
| `executable-demonstration` |  | run \| cached |  | clean \| findings |  |
| `decision-reconciliation` |  | run \| cached |  | clean \| findings |  |

Always-run tier — never cached, because it is cheap, deterministic, and model-independent:

| Check | Result | What it does not prove |
| --- | --- | --- |
| Mechanical, link, generator, and rendered-output validation |  |  |
| Guard regression — every guard from a previous finding still fires |  |  |
| Residual exhaustion — only when a pass produced a finding |  |  |

### Method versions bumped by this review

Each bump reopens that pass for every project on the next review. Leave empty if none.

| id | Old → new | What the old method missed |
| --- | --- | --- |
|  |  |  |

### Findings mechanized into guards

The durable output of a review. A finding that could have been mechanized and was not will be
rediscovered by hand every time — record why.

| Finding | Guard added (and where it runs) | Verified to fire on the original fault | If not mechanized, why |
| --- | --- | --- | --- |
|  |  |  |  |

## Material-claim ledger

Record every claim that affects security, compliance, standards, protocol or implementation behavior, numerical limits, threat models, or engineering decisions.

| ID | Artifact and location | Material claim | Classification | Primary source or verification | Repetitions checked | Result |
| --- | --- | --- | --- | --- | --- | --- |
| C-001 |  |  |  |  |  | Open |

## Topic completeness matrix

Use **covered**, **not applicable** with a reason, **required gap**, or **optional extension**. Add one row per topic.

| Topic | Definition | Boundaries | Actors/components | Mechanism/sequence | Assumptions/dependencies | Threats/failures | Limits/residual risk | Selection/use | Operations/evidence | Recovery/lifecycle | Interoperability/migration | Unsafe alternatives | Visual representation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |  |  |  |  |  |  |  |  |

## Argument integrity

What the verified claims add up to. Every other section decomposes the content; this one recomposes it. A finding here is structural — resolved by adding, removing, reordering, or reframing, not by correcting a sentence.

**Central claim, in one sentence (extracted from title, lede, and summary):**

| Test | Result | Evidence or finding |
| --- | --- | --- |
| Thesis support — do the cited sources support that claim at that strength and scope? |  |  |
| Comparison-set validity — is every compared element an option the reader can select, is the set complete, does one axis run through it? |  |  |
| Demonstration sufficiency — does each demonstration show both sides of the contrast it teaches, with other variables held constant? |  |  |
| Dangling claims — is every threat, mechanism, limit, or term introduced either developed or removed? |  |  |
| Structure serves the decision — does section order and heading language match how the reader needs to act? |  |  |

## Cross-format and cross-page ledger

| Concept or claim | Representations compared | Result |
| --- | --- | --- |
|  |  |  |

## Visual content ledger

One row per diagram, figure, chart, or screenshot. Assessed independently of the prose — agreement with the text is not correctness.

| Visual | Claims it asserts (labels, arrows, ordering, axes, units, legend, annotated values) | Independently correct? | Self-sufficient when detached (scope, units, qualifiers)? | Caption and alt text verified | Generator and correspondence check | Standalone defensibility (weakness visuals) | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |  |  |

### Representation opportunities

Where dense prose would be materially clearer as a visual. Optional extension by default; required gap only where the prose is hard to follow without one.

| Location | What is dense | Proposed form | Required gap or optional extension |
| --- | --- | --- | --- |
|  |  |  |  |

## Applicable durable content decisions

Evaluate current source and evidence before consulting the register. Record every decision returned for the reviewed files or concepts.

| Decision ID | Affected concept | Disposition: reaffirmed / not applicable / reopened / superseded | Current evidence and rationale |
| --- | --- | --- | --- |
|  |  |  |  |

## Mechanical and rendered checks

| Check | Scope | Result | What this does not prove |
| --- | --- | --- | --- |
|  |  |  |  |

## Open required findings

For each finding, record the artifact and location, exact issue, classification, practical impact, reasoning, primary source when applicable, and explicit correction.

None recorded yet.

## Optional coverage

None recorded yet.

## Limitations and uncertainty

Record inaccessible sources, unsupported environments, unrendered assets, ambiguous scope, and any sampling. Sampling is a disclosed limitation and cannot support a complete-review claim for the sampled dimension.

None recorded yet.

## Closure attestation

- [ ] Every pass is either run-and-clean or validly cached, and every cached one names the run it rests on.
- [ ] The router's RUN/CACHED split was followed, not overridden by judgement or by how the request was phrased.
- [ ] Every in-scope artifact covered by a running pass was inventoried and read in full.
- [ ] Every material claim was entered in the ledger and dispositioned.
- [ ] Every topic received a completeness classification for every category.
- [ ] Every mandatory pass was completed separately, or is validly cached.
- [ ] Current primary sources were used for standards-sensitive and time-sensitive claims, or their pass is inside its decay horizon.
- [ ] Prose, metadata, diagrams, captions, alt text, examples, summaries, navigation, and generators were reconciled.
- [ ] Every visual was reviewed as its own artifact for independent correctness, detached self-sufficiency, generator provenance, and standalone defensibility, separately from the cross-format pass.
- [ ] Applicable mechanical and rendered checks passed or their limitations are recorded.
- [ ] Applicable durable content decisions were reconciled after the independent claim review, and every reversal or supersession is justified.
- [ ] The argument-integrity pass was completed and the one-sentence thesis recorded.
- [ ] Residual exhaustion was completed after findings were assembled.
- [ ] Every guard from a previous finding was executed and still fires.
- [ ] Each remediated finding gained a guard, or the reason it could not be mechanized is recorded.
- [ ] The pass state was written with `review_passes.py --record`, naming only passes that actually ran.
- [ ] The baseline remained frozen, or changes and repeated passes are documented.
- [ ] Required findings, optional coverage, and limitations are separated.

Closure conclusion:
