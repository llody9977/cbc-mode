# Fresh review record: whole project

> Lives at `reviews/LATEST_REVIEW.md` and is overwritten by each new review — this file always holds the
> most recent one. Earlier records are in git, not in this folder:
> `git log -p --follow reviews/LATEST_REVIEW.md` for the full series,
> `git show <commit>:reviews/LATEST_REVIEW.md` for one in full.

## Status and baseline

- Status: Complete with no open findings
- Review mode: Fresh review (closure review of the state remediated after the review recorded at `83fbcb7`)
- Review date: 2026-08-23
- Reviewer: Claude Code (doc-review skill, whole-project scope)
- Branch: fix/review-16ade34-findings
- Commit: `b40b896e0530cc627f1086462ba3e8c9a6c52c4d`
- Worktree: Clean
- Review state ID: `03a1f3fc039c2e2aa104ac12b07fde3c311fe246ce04bbc5a09c8bf25fc7656f`
- Scoped content fingerprint: `8963e13d3549e76197535ff16b240396f1db8accf30d5859ef315635ebc0c3a5`
- State-capture command: `python3 scripts/capture_review_state.py --scope README.md --scope DISCLAIMER.md --scope SECURITY.md --scope CONTRIBUTING.md --scope docs --scope test`
- Baseline changed during review: **Yes, once, and handled.** Passes ran against `83fbcb7` (fingerprint `4d51a243…`) and produced three findings. Those were fixed in `b40b896`, a new baseline was captured, and the affected passes — factual correctness on the changed unit, cross-format, and all mechanical checks — were repeated against it. Unaffected passes (visual content, decision reconciliation, topic completeness) were not repeated because `b40b896` touches only three prose regions of `docs/index.html`.

### Review lineage

| Baseline | Fingerprint | Outcome |
| --- | --- | --- |
| `16ade34` | `7745a5d6…` | Fresh review — 10 required findings, 9 optional gaps. Record retrievable with `git show 83fbcb7:reviews/LATEST_REVIEW.md`. |
| `27c1e44`, `131a349` | — | Remediation of those findings, plus F-11 found once the first fix stopped masking it. |
| `83fbcb7` | `4d51a243…` | Closure review — 3 findings (one pre-existing and previously missed, two introduced by the remediation). |
| `b40b896` | `8963e13d…` | **This record.** Closure findings fixed; affected passes repeated; no open findings. |

## Scope inventory

| Artifact | Type | Direct dependents or generated counterpart | Inspected |
| --- | --- | --- | --- |
| `README.md` | doc | `docs/diagrams/taxonomy.svg` (embedded) | Yes |
| `docs/index.html` | doc (primary) | `styles.css`, `docs/js/*.mjs`, all 6 SVGs | Yes — re-read in full at `83fbcb7`, changed regions re-read at `b40b896` |
| `docs/styles.css` | presentation | `docs/index.html` | Yes |
| `docs/js/crypto.mjs` | code | `attacks.mjs`, `ui.mjs`, `test/` | Yes |
| `docs/js/attacks.mjs` | code | `ui.mjs`, `test/` | Yes |
| `docs/js/ui.mjs` | code | `docs/index.html` | Yes |
| `docs/diagrams/generate_diagrams.py` | generator | all 6 committed SVGs | Yes |
| `docs/diagrams/*.svg` (6 files) | generated figures | `docs/index.html`, `README.md` | Yes |
| `test/attacks.test.mjs` | test | `docs/js/*.mjs` | Yes — 10/10 passing |
| `DISCLAIMER.md`, `SECURITY.md`, `CONTRIBUTING.md` | doc / policy | — | Yes |
| `package.json`, `eslint.config.mjs`, `.pre-commit-config.yaml`, `.github/workflows/ci.yml` | config | `npm test`, `npm run lint`, secret gate, EOF hook | Yes |
| `reviews/CONTENT_DECISIONS.yml` | registry | `scripts/verify_content_decisions.py` | Yes — 8 decisions |

Out-of-scope boundaries and reason: `LICENSE` (verbatim canonical Apache-2.0), `package-lock.json` (generated), `node_modules/` (vendored), `reviews/REVIEW_TEMPLATE.md` and `reviews/CONTENT_DECISION_GUIDE.md` (bootstrapped verbatim from the doc-review skill; not editable locally).

## Review passes

| Pass | Complete | Evidence or notes |
| --- | --- | --- |
| Factual and technical correctness | Yes | Re-derived every corrected claim against its source. Repeated at `b40b896` for the three changed regions. Produced CR-02. |
| Evidence, authority, version, date, jurisdiction, and applicability | Yes | Every citation corrected at `131a349` re-checked against the primary text and re-resolved over the network. See CD-0002. |
| Adversarial wording, assumptions, attacker state, and counterexamples | Yes | Challenged the remediation's own new numbers, which is what produced CR-02 and CR-03. |
| Terminology, taxonomy, and conceptual boundaries | Yes | EtM / MtE / E&M boundary now defined (CD-0007); root-cause-to-vector mapping unchanged and reaffirmed. |
| Cross-format consistency | Yes | Repeated at `b40b896`: the only other occurrence of the BEAST candidate count is the code that constructs the list, and it agrees. |
| Visual content review (independent correctness and defensibility) | Yes | All six SVGs re-derived from the generator and inspected rendered. Not repeated at `b40b896` — no visual changed. |
| Cross-page consistency, prerequisites, sequence, and duplication | Yes | README ↔ page ↔ footer ↔ tests now describe the same test scope; no residual contradiction. |
| Topic completeness | Yes | All prior required gaps closed; matrix below. |
| Mechanical, link, generator, executable, and rendered-output validation | Yes | Fully repeated at `b40b896`. Produced CR-01. |
| Durable content-decision reconciliation | Yes | All 8 records reconciled; see table. |
| Residual exhaustion | Yes | Ran at `83fbcb7` (produced CR-01, CR-02, CR-03) and again at `b40b896` (no further findings). |

## Material-claim ledger

Claims settled by a durable decision reference it rather than restating its sources.

| ID | Artifact and location | Material claim | Classification | Primary source or verification | Repetitions checked | Result |
| --- | --- | --- | --- | --- | --- | --- |
| C-001 | `index.html` "The mechanism" | CBC encrypt/decrypt equations | Mathematical | SP 800-38A §6.2 | prose, `modes-cbc-vs-gcm.svg`, `attacks.mjs` header | Closed |
| C-002 | `index.html` Vector 3, refs | IV "must be unpredictable" | Standards attribution | See CD-0002 — verbatim §6.2 | prose, refs | Closed |
| C-003 | `index.html` Vector 1 | `Cᵢ₋₁[j] ⊕ Δ` yields `Pᵢ[j] ⊕ Δ` | Mathematical | Test + live browser run | prose, SVG, `ui.mjs` tag | Closed |
| C-004 | `index.html` Vector 2 + callout | Oracle reports block-wide PKCS#7 validity; a second candidate can pass | Algorithmic | See CD-0004 | prose, callout, SVG, `attacks.mjs` guard | Closed |
| C-005 | `index.html` Vector 2, demo hint | ≈128 oracle calls per byte; ≈`256 × L` worst case | Numerical limit | **60 randomized runs: mean 8192 queries, 128.0/byte, min 6848, max 10699, 60/60 exact** | prose, callout, SVG, README, hint, test bound | Closed — measurement matches the stated average exactly |
| C-006 | `index.html` Vector 3 | Predictable IV breaks IND-CPA (BEAST) | Security / CVE | CVE-2011-3389; see CD-0002 for the citation | prose, SVG, table, README | Closed |
| C-007 | `index.html` Vector 3 demo hint | ≤95 probe requests for printable ASCII, ≤256 otherwise | Numerical limit | Candidate list derived: 256 unique values, 95 printable | hint vs `BEAST_CANDIDATES` | **CR-02** — was "up to 95" flat; corrected |
| C-008 | `index.html` Vector 4 + callout | CBC-R forgery, conditional on attacker-supplied IV | Attack capability | See CD-0003 | prose, callout, SVG, README, demo verdict | Closed |
| C-009 | `index.html` Vector 4 | CBC-R originates with Rizzo & Duong 2010 | Attribution | See CD-0002 | prose, refs | Closed |
| C-010 | `index.html` refs, table | BEAST paper provenance and status | Citation / venue | See CD-0002 | prose ×2, refs | Closed |
| C-011 | `index.html` residual risk | Deterministic IV capped at `2^s`; RBG capped at 2³² | Standards specification | See CD-0005 | prose, refs | Closed |
| C-012 | `index.html` real-world table | POODLE ≈256 requests/byte; Sweet32 ≈32 GB at 2³² blocks | Numerical | POODLE paper verbatim; 2³² × 8 B = 32 GiB | table, README | Closed |
| C-013 | `index.html` fix section | EtM verifies before decrypting; MtE is what Lucky 13 attacked | Security / composition | See CD-0007 | prose, table row | Closed |
| C-014 | `index.html` footer, README | NIST vectors validate the cipher, not the attacks | Evidence claim | Test 1 uses the vectors; attack tests use random keys | footer, README, test header | Closed |
| C-015 | `README.md`, lede | Every attack runs live in the browser | Capability claim | All five demos driven end-to-end in a browser | README, lede, footer | Closed |
| C-016 | `test/attacks.test.mjs` | AES-128-CBC matches SP 800-38A §F.2.1 | Test vector | Key, IV, and all four ciphertext blocks match verbatim | test, README, footer | Closed |
| C-017 | `index.html` residual risk | GCM nonce reuse compromises GHASH key H | Security | eprint 2016/475 (Böck et al., WOOT 2016) | prose | Closed |
| C-018 | `index.html` Vector 4 | Step list is a sibling of its paragraphs | Markup correctness | Document parsed; rendered DOM walked | prose region | **CR-01** — `<ol>` was inside `<p>`; corrected |

## Topic completeness matrix

| Topic | Definition | Boundaries | Actors/components | Mechanism/sequence | Assumptions/dependencies | Threats/failures | Limits/residual risk | Selection/use | Operations/evidence | Recovery/lifecycle | Interoperability/migration | Unsafe alternatives | Visual representation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CBC mechanism | covered | covered | covered | covered | covered | covered | covered | covered | covered | n/a — mode level | covered | covered | covered |
| V1 bit-flipping | covered | covered | covered | covered | covered | covered | covered | covered | covered | n/a | covered | covered | covered |
| V2 padding oracle | covered | covered | covered | covered | covered | covered (false positive now stated) | covered | covered | covered | n/a | covered | covered | covered |
| V3 predictable IV | covered | covered | covered | covered | covered (`B_target` defined) | covered | covered | covered | covered | n/a | covered | covered | covered |
| V4 CBC-R forgery | covered | covered | covered | covered | covered (IV prerequisite) | covered | covered (IV prerequisite) | covered | covered | n/a | covered | covered | covered |
| AEAD remediation | covered | covered | covered | covered | covered | covered | covered | covered | covered | covered (rekeying) | covered | covered (EtM/MtE/E&M) | optional extension |
| GCM residual risk | covered | covered | covered | covered | covered | covered | covered (both ceilings) | covered | covered | covered | covered | covered | optional extension |
| Detection guidance | covered | covered | covered | covered | covered | covered | covered | covered | covered | n/a | covered | covered | optional extension |

No required gaps remain. Every category is covered, not applicable with a stated reason, or classified as an optional extension.

## Cross-format and cross-page ledger

| Concept or claim | Representations compared | Result |
| --- | --- | --- |
| CBC-R capability and IV prerequisite | prose, callout, README bullet, `vector4-cbc-r-forgery.svg`, demo verdict | All five agree |
| Padding-oracle validity test | prose, callout, SVG, `attacks.mjs` guard and comment | All four agree |
| Padding-oracle query cost | prose, callout, SVG, README, demo hint, test bound | All six agree; hint's figure re-measured over 60 runs |
| BEAST probe cost | demo hint vs `BEAST_CANDIDATES` construction | Agrees after CR-02 |
| BEAST notation `B_target` | prose, `vector3-predictable-iv.svg` alt text | Agrees |
| BEAST citation | prose ×2, Primary references | Agrees; dead URL survives only in the superseded CD-0001 |
| SP 800-38A IV wording | prose, Primary references | Agrees |
| SP 800-38D ceilings | prose, Primary references | Agrees |
| Test-suite evidence scope | footer, README `test/` bullet, test file header | All three agree |
| Diagram semantic colors | 6 SVGs vs generator docstring | One convention, applied throughout |

## Visual content ledger

No visual changed at `b40b896`; this table records the state verified at `83fbcb7` and unchanged since.

| Visual | Claims it asserts | Independently correct? | Self-sufficient when detached | Caption and alt text verified | Generator and correspondence check | Standalone defensibility | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `modes-cbc-vs-gcm.svg` | CBC feedback path, GCM tag-verify-before-release | Yes | Yes — scope line inside | Alt text conveys the conclusion | Regenerated; byte-identical | Yes | Closed |
| `taxonomy.svg` | 3 root causes → 4 vectors, attacker-mode labels | Yes | Yes — scope line inside | Alt text lists causes and vectors | Regenerated; byte-identical | Yes | Closed |
| `vector1-bit-flipping.svg` | Profile string, byte offsets, Δ = 0x01, scrambled P′[1], forged P′[2] | Yes — string now matches the code; Δ stated correctly | Yes | Alt text rewritten with the delta and the scrambled block | Regenerated; matches source | Yes — local service named | Closed |
| `vector2-padding-oracle.svg` | Block-wide validity, recheck step, `I[15]` derivation, query cost | Yes — biconditional removed | Yes | Alt text rewritten with the false-positive step | Regenerated; matches source | Yes — local mock oracle named | Closed |
| `vector3-predictable-iv.svg` | Chained-IV rule, `P_guess` formula, match condition | Yes | Yes — names CVE-2011-3389 and the local session | Alt text rewritten with the formula | Regenerated; matches source | Yes — "educational simulation" stated | Closed |
| `vector4-cbc-r-forgery.svg` | Backward synthesis, `C[n-1] = I[n] ⊕ P[n]`, IV prerequisite | Yes — REQUIRES line added | Yes — prerequisite now inside the artifact | Alt text rewritten with the limitation | Regenerated; matches source | Yes — local oracle named | Closed |

Provenance: the generator is idempotent — run twice, hashes identical, no working-tree diff — so the committed artifacts and their source cannot drift silently under the repository's `end-of-file-fixer` hook.

### Representation opportunities

| Location | What is dense | Proposed form | Required gap or optional extension |
| --- | --- | --- | --- |
| Vector 3 BEAST alignment | Block alignment as `i` passes a block boundary, carried by algebra | Block-offset strip showing filler shrinking as recovered bytes fill in | Optional extension — and the exact area where the implementation was wrong, so a figure would have review value beyond the reader's |
| EtM / MtE / E&M ordering | Three compositions distinguished only in prose | Three-row sequence comparison showing where verification sits relative to unpadding | Optional extension |

## Applicable durable content decisions

| Decision ID | Affected concept | Disposition | Current evidence and rationale |
| --- | --- | --- | --- |
| CD-0001 | Original taxonomy record | **Superseded** (by CD-0002) | Preserved unedited as history. Its dead IACR URL and Vaudenay/CBC-R attribution remain in the record deliberately; neither appears in live content. |
| CD-0002 | Taxonomy; source attributions; demo verification | **Reaffirmed** | Verified in current source: CBC-R credited to Rizzo & Duong, BEAST cited as a Netifera white paper via a resolving archived URL, SP 800-38A quoted as "must". All ten vectors/demos exercised. |
| CD-0003 | CBC-R IV prerequisite | **Reaffirmed** | Present in prose callout, README, SVG, and demo verdict. |
| CD-0004 | Block-wide padding-oracle validity | **Reaffirmed** | Present in prose callout and SVG; matches the code guard; query bound re-measured. |
| CD-0005 | SP 800-38D IV ceilings | **Reaffirmed** | Both ceilings present with section numbers and quoted text. |
| CD-0006 | Diagram color convention | **Reaffirmed** | Convention documented in the generator docstring and applied in all six SVGs. |
| CD-0007 | EtM vs MtE coverage | **Reaffirmed** | Subsection present; RFC 7366 resolves. |
| CD-0008 | textContent-only demo output | **Reaffirmed** | `grep innerHTML docs/js/ui.mjs` returns only the two comment lines that state the rule. |

No decision was reopened or reversed at this baseline.

## Mechanical and rendered checks

| Check | Scope | Result | What this does not prove |
| --- | --- | --- | --- |
| `node --test` | all modules | 10/10 | Coverage of the paths tested, not of paths no test names |
| `npm run lint` | all `.mjs` | Clean | Nothing about factual accuracy or runtime behavior |
| HTML nesting parse | `docs/index.html` | Clean after CR-01 | Element nesting only; not CSS, accessibility, or semantics |
| Live browser run | all 5 demos | All correct — V2 exact in 8094 queries, V3 exact 25/25, V1/V4/GCM exact | Chromium at dark scheme, desktop width only |
| XSS probe | `bf-user`, `frg-payload` | 0 injected nodes, no execution, payload literal | The sinks reachable from demo inputs, not a full audit |
| Padding-oracle measurement | 60 randomized runs, page default secret, with `onProgress` | 60/60 exact; mean 8192, median 8227, min 6848, max 10699; 128.0 queries/byte | Not a worst-case proof; evidence for the stated average |
| BEAST candidate derivation | `BEAST_CANDIDATES` | 256 unique values, 95 printable | — |
| Generator idempotence | 6 SVGs | Two runs, identical hashes, no diff | That the figures are conceptually correct — the visual ledger's job |
| External link check | all URLs in README and page | All resolve (the only non-200 is the `localhost:8000` preview instruction) | That a reachable URL supports the claim beside it |
| Console on load | `docs/index.html` | No errors | Errors only surfacing under interaction paths not exercised |
| `verify_content_decisions.py` | register | 8 decisions validated | Structure and references only, not technical correctness |
| `pre-commit run --all-files` | all staged content | Passed — gitleaks, private key, large files, merge conflicts, EOF, trailing whitespace | That no secret exists, only that none matched a rule |

## Open required findings

None.

The three findings raised by this closure review against `83fbcb7` are resolved in `b40b896`:

| ID | Location | Finding | Resolution |
| --- | --- | --- | --- |
| CR-01 | `index.html` Vector 4 | `<ol>` opened inside an open `<p>`, which HTML does not permit — the parser auto-closed the paragraph and orphaned the closing tag, leaving the sentence after the list outside any paragraph. **Pre-existing at `16ade34`; missed by the previous review's residual pass.** | List and both paragraphs made siblings; verified by parsing the document and by walking the rendered DOM |
| CR-02 | `index.html` Vector 3 demo hint | "Each byte costs up to 95 chosen-plaintext requests" — 95 is the printable-ASCII case; the candidate list covers all 256 values and the field is user-editable. **Introduced by the remediation at `131a349`.** | Restated with both figures plus the per-byte capture request |
| CR-03 | `index.html` Vector 2 demo hint | A "30–60 seconds" runtime taken from a sandboxed browser subject to background-timer throttling — a figure this review could not support. **Introduced by the remediation at `131a349`.** | Replaced with the measured invariant (≈128 calls/byte, on the order of 8,000 decryptions) and a pointer to the exact count the demo prints |

## Optional coverage

All nine optional gaps from the `16ade34` review are addressed. Two representation opportunities remain open by choice and are recorded above as optional extensions; neither is a correctness defect, and the prose stands without them.

## Limitations and uncertainty

- **Vaudenay EUROCRYPT 2002 full text is paywalled** (Springer returns a 303 to an IdP flow). The CBC-R attribution rests on the Rizzo & Duong WOOT 2010 primary text, which is decisive standing alone. The negative claim — that Vaudenay 2002 does not contain CBC-R — is supported by that paper's statement, not by reading Vaudenay directly.
- **Browser coverage is partial.** Rendered checks ran in the in-app Chromium at the dark color scheme and desktop width. Safari, Firefox, light scheme, and mobile widths were not exercised.
- **GitHub-side rendering unverified.** Whether `taxonomy.svg`'s `prefers-color-scheme` block survives GitHub's image proxy in the rendered README was not checked in the GitHub UI.
- **Browser timing is environmental.** The padding-oracle demo stalls when the browser pane is hidden (background-timer throttling) and resumes when fronted. This is why CR-03 exists: no wall-clock figure is asserted on the page. Correctness and cost were established in Node instead, over 60 runs.
- **Worst-case query bounds are not proven,** only bounded by measurement across 60 runs plus the structure of the false-positive recheck.
- **Passes were not all repeated at `b40b896`.** `b40b896` changes three prose regions of `docs/index.html` and nothing else. Factual correctness on those regions, cross-format, and every mechanical check were repeated; the visual, decision-reconciliation, and completeness passes were not, because no artifact in their scope changed.
- **This branch is unmerged.** The record describes `fix/review-16ade34-findings`, not `main`, and the published GitHub Pages site still serves the `16ade34` content until this is merged and deployed.

## Closure attestation

- [x] Every in-scope artifact was inventoried and read in full.
- [x] Every material claim was entered in the ledger and dispositioned.
- [x] Every topic received a completeness classification for every category.
- [x] Every mandatory pass was completed separately.
- [x] Current primary sources were used for standards-sensitive and time-sensitive claims.
- [x] Prose, metadata, diagrams, captions, alt text, examples, summaries, navigation, and generators were reconciled.
- [x] Every visual was reviewed as its own artifact for independent correctness, detached self-sufficiency, generator provenance, and standalone defensibility, separately from the cross-format pass.
- [x] Applicable mechanical and rendered checks passed or their limitations are recorded.
- [x] Applicable durable content decisions were reconciled after the independent claim review; none required reversal at this baseline.
- [x] Residual exhaustion was completed after findings were assembled, at both `83fbcb7` and `b40b896`.
- [x] The baseline change is documented, along with which passes were repeated and why the others were not.
- [x] Required findings, optional coverage, and limitations are separated.

Closure conclusion: **Commit `b40b896` (fingerprint `8963e13d…`) carries no open required findings.** Every claim in the material-claim ledger is closed against a primary source or a direct measurement, every completeness category is covered or classified, all eight durable decisions are reaffirmed, and every mechanical check passes. The closure review found three defects in the remediated state — one pre-existing and missed by the previous pass, two introduced by the remediation itself — which is the expected yield of reviewing a changed state rather than trusting the change. Closure applies to this branch only; the deployed site still serves `16ade34` until the branch is merged. The limitations above are real and undischarged: they bound what this record claims, and they do not expire.
