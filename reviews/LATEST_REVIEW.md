# Fresh review record: whole project

> Lives at `reviews/LATEST_REVIEW.md` and is overwritten by each new review — this file always holds the
> most recent one. Earlier records are in git, not in this folder:
> `git log -p --follow reviews/LATEST_REVIEW.md` for the full series,
> `git show <commit>:reviews/LATEST_REVIEW.md` for one in full.

## Status and baseline

- Status: Complete with findings — all findings remediated in the working tree, pending commit
- Review mode: Fresh review, followed by an authorized remediation phase
- Review date: 2026-08-23
- Reviewer: Claude Code (doc-review skill, whole-project scope)
- Branch: main
- Commit: `16ade34c8336b995bdc07fbb6d0c2b1a776d7ae7`
- Worktree at review time: Clean
- Review state ID: `e3c5505587c8a9bd713534aed96d9690a4bbd6bd87ea6df6072dfe7ea7213924`
- Scoped content fingerprint: `7745a5d6c0594d9742c2c5f47dd98b0b2a5406951e3a9fec7582562d86dd4b8e`
- State-capture command: `python3 scripts/capture_review_state.py --scope README.md --scope DISCLAIMER.md --scope SECURITY.md --scope CONTRIBUTING.md --scope docs --scope test`
- Baseline changed during review: No. The review ran to completion against the frozen clean state above; remediation began only afterwards, as a separate phase.
- Post-remediation state: commit `16ade34` with a dirty worktree, fingerprint `4645fc174715fe9d7db1b9823bd9cd44d3c36422ed8109dc4449d73071b9feee`, state ID `a752cd396e6b05606f1da90992abd317b8d064c27b3aecd5cae3ea123c7b582f`. Modified: `README.md`, `docs/index.html`, `docs/js/{attacks,crypto,ui}.mjs`, `docs/diagrams/generate_diagrams.py`, `docs/diagrams/vector{1,2,3,4}-*.svg`, `test/attacks.test.mjs`, `reviews/CONTENT_DECISIONS.yml`. A closure review of the remediated state requires a fresh baseline and repeated passes.
- Deployment check: at review time the GitHub Pages site served `index.html`, `attacks.mjs`, `crypto.mjs`, and `ui.mjs` byte-identical (SHA-256) to the reviewed baseline, so every finding below was live for readers.

## Scope inventory

| Artifact | Type | Direct dependents or generated counterpart | Inspected |
| --- | --- | --- | --- |
| `README.md` | doc | `docs/diagrams/taxonomy.svg` (embedded) | Yes |
| `docs/index.html` | doc (primary) | `styles.css`, `docs/js/*.mjs`, all 6 SVGs | Yes |
| `docs/styles.css` | presentation | `docs/index.html` | Yes |
| `docs/js/crypto.mjs` | code | `attacks.mjs`, `ui.mjs`, `test/` | Yes |
| `docs/js/attacks.mjs` | code | `ui.mjs`, `test/` | Yes |
| `docs/js/ui.mjs` | code | `docs/index.html` | Yes |
| `docs/diagrams/generate_diagrams.py` | generator | all 6 committed SVGs | Yes |
| `docs/diagrams/modes-cbc-vs-gcm.svg` | generated figure | `docs/index.html` | Yes |
| `docs/diagrams/taxonomy.svg` | generated figure | `docs/index.html`, `README.md` | Yes |
| `docs/diagrams/vector1-bit-flipping.svg` | generated figure | `docs/index.html` | Yes |
| `docs/diagrams/vector2-padding-oracle.svg` | generated figure | `docs/index.html` | Yes |
| `docs/diagrams/vector3-predictable-iv.svg` | generated figure | `docs/index.html` | Yes |
| `docs/diagrams/vector4-cbc-r-forgery.svg` | generated figure | `docs/index.html` | Yes |
| `test/attacks.test.mjs` | test | `docs/js/*.mjs` | Yes — 7/7 at baseline, 10/10 after remediation |
| `DISCLAIMER.md`, `SECURITY.md`, `CONTRIBUTING.md` | doc / policy | — | Yes |
| `package.json`, `eslint.config.mjs`, `.pre-commit-config.yaml`, `.github/workflows/ci.yml` | config | `npm test`, `npm run lint`, EOF hook | Yes |
| `reviews/CONTENT_DECISIONS.yml` | registry | `scripts/verify_content_decisions.py` | Yes |
| Live GitHub Pages deployment | rendered output | `docs/` | Yes — hash-compared to baseline |

Out-of-scope boundaries and reason: `LICENSE` (verbatim canonical Apache-2.0), `package-lock.json` (generated), `node_modules/` (vendored dependencies), `reviews/REVIEW_TEMPLATE.md` and `reviews/CONTENT_DECISION_GUIDE.md` (bootstrapped verbatim from the doc-review skill; not editable locally).

## Review passes

| Pass | Complete | Evidence or notes |
| --- | --- | --- |
| Factual and technical correctness | Yes | Re-derived the CBC equations, the bit-flip delta identity, the padding-oracle recovery loop, the BEAST alignment arithmetic, and the CBC-R backward synthesis. Produced F-04 and F-07. |
| Evidence, authority, version, date, jurisdiction, and applicability | Yes | Extracted SP 800-38A and SP 800-38D from the NIST PDFs and the WOOT 2010 paper from USENIX; quoted directly. Produced F-03, F-05, F-06, F-08. |
| Adversarial wording, assumptions, attacker state, and counterexamples | Yes | Challenged "exactly one", "100% valid padding", "no invocation limit", and the bolded "shall". Produced F-04, F-06, F-07, F-08. |
| Terminology, taxonomy, and conceptual boundaries | Yes | Root-cause-to-vector mapping holds. Found the EtM/MtE boundary undefined while both terms were used (O-01). |
| Cross-format consistency | Yes | README ↔ index.html ↔ js ↔ tests ↔ 6 SVGs compared claim by claim. Produced F-04, F-10, O-04. |
| Visual content review (independent correctness and defensibility) | Yes | Separate pass; see the visual content ledger. Produced F-04, F-07, O-03, O-04, O-07. |
| Cross-page consistency, prerequisites, sequence, and duplication | Yes | README, DISCLAIMER, SECURITY, CONTRIBUTING consistent in scope and authorization language. No defects. |
| Topic completeness | Yes | Full 13-category matrix below. Required gaps: assumptions, threats, limits. |
| Mechanical, link, generator, executable, and rendered-output validation | Yes | See mechanical checks table. Produced F-01, F-02, F-05, F-09, O-05. |
| Durable content-decision reconciliation | Yes | CD-0001 evaluated after independent claim review; reopened and superseded. |
| Residual exhaustion | Yes | Re-read every affected unit after findings were assembled. Produced F-07, F-10, O-05, O-06, O-07, and — during remediation — F-11. |

## Material-claim ledger

| ID | Artifact and location | Material claim | Classification | Primary source or verification | Repetitions checked | Result |
| --- | --- | --- | --- | --- | --- | --- |
| C-001 | `index.html` "The mechanism" | `Cᵢ = E_K(Pᵢ ⊕ Cᵢ₋₁)`, `Pᵢ = D_K(Cᵢ) ⊕ Cᵢ₋₁` | Mathematical | SP 800-38A §6.2, quoted | prose, `modes-cbc-vs-gcm.svg`, `attacks.mjs` header | Closed — accurate |
| C-002 | `index.html` Vector 3, refs | CBC requires an unpredictable IV | Standards attribution | SP 800-38A §6.2 verbatim: "must be unpredictable" | prose ×2, refs, CD-0001 | **F-08** — "shall" misquoted; fixed |
| C-003 | `index.html` Vector 1 | Modifying `Cᵢ₋₁[j]` yields `Pᵢ[j] ⊕ Δ` | Mathematical | Test + live browser run | prose, `vector1-bit-flipping.svg`, `ui.mjs` | Closed — accurate (label defects O-04) |
| C-004 | `index.html` Vector 2 | One candidate ends the block in valid padding `0x01` | Algorithmic | Contradicted by `attacks.mjs` guard; 40× stress run | prose, `vector2-padding-oracle.svg` | **F-07** — false; fixed |
| C-005 | `index.html` Vector 2 | Recovery costs at most `256 × L` queries | Numerical limit | Max observed 9241 for L=64; recheck can exceed bound | prose, SVG, README, `attacks.mjs`, test assert | **F-07 / O-06** — softened; test bound widened |
| C-006 | `index.html` Vector 3 | Predictable IV breaks IND-CPA (BEAST) | Security / CVE | CVE-2011-3389; Netifera white paper | prose, SVG, table, README | Closed — accurate; citation **F-05**, demo **F-02** |
| C-007 | `index.html` Vector 4 | Padding oracle enables arbitrary ciphertext forgery | Attack capability | WOOT 2010 §4.1 | prose, SVG, README, `ui.mjs` verdict | **F-04** — IV prerequisite omitted; fixed |
| C-008 | `index.html` Vector 4 | CBC-R attributable to Vaudenay 2002 | Attribution | WOOT 2010: "We call it CBC-R encryption" | prose, CD-0001 | **F-03** — false; fixed |
| C-009 | `index.html` refs, table | BEAST paper is CRYPTO 2011 | Citation / venue | Netifera white paper 13 May 2011, ekoparty; URL 404 | prose ×2, refs, CD-0001 | **F-05** — false venue + dead link; fixed |
| C-010 | `index.html` residual risk | 96-bit deterministic IVs have no invocation limit | Standards specification | SP 800-38D §8.3: constraints apply "including 96 bits", cap `2^s` | prose only | **F-06** — contradicts source; fixed |
| C-011 | `index.html` residual risk | RBG IVs capped at 2³² encryptions per key | Standards specification | SP 800-38D §8.3 verbatim | prose, refs | Closed — accurate; §8.2.2 wording tightened (O-08) |
| C-012 | `index.html` real-world table | POODLE ≈256 requests per byte | Numerical | POODLE paper: "expected overall effort is 256 SSL 3.0 requests per byte" | table, README | Closed — accurate |
| C-013 | `index.html` real-world table | Sweet32: ≈32 GB / 2³² blocks, 64-bit ciphers | Numerical | 2³² × 8 B = 32 GiB; CVE-2016-2183 | table | Closed — accurate |
| C-014 | `index.html` real-world table | Lucky 13 affects TLS 1.1/1.2 CBC MtE | Security / CVE | NVD CVE-2013-0169 scope | table | Closed — consistent with the cited CVE |
| C-015 | `index.html` footer | Primitives **and attack logic** verified against NIST vectors | Evidence claim | Only test 1 uses NIST vectors; attack tests use random keys | footer vs README | **F-10** — overclaim; fixed |
| C-016 | `README.md`, `index.html` lede | Every attack runs live in your browser | Capability claim | Live browser run of all five demos | README, lede, footer | **F-01 / F-02** — false for Vectors 2 and 3; fixed |
| C-017 | `test/attacks.test.mjs` | AES-128-CBC matches NIST SP 800-38A §F.2.1 | Test vector | Key, IV, and all four ciphertext blocks match the spec verbatim | test, README, footer | Closed — accurate |
| C-018 | `index.html` fix section | TLS 1.3 removed CBC in favor of AEAD | Standards | RFC 8446 | prose, table, refs | Closed — accurate |
| C-019 | `index.html` residual risk | GCM nonce reuse compromises GHASH key H | Security | eprint 2016/475 (Böck et al., WOOT 2016) | prose | Closed — accurate |
| C-020 | `index.html` detection | Grep for CBC without HMAC verification | Operational guidance | Incomplete without EtM/MtE ordering | prose | **O-01** — gap; addressed |

## Topic completeness matrix

| Topic | Definition | Boundaries | Actors/components | Mechanism/sequence | Assumptions/dependencies | Threats/failures | Limits/residual risk | Selection/use | Operations/evidence | Recovery/lifecycle | Interoperability/migration | Unsafe alternatives | Visual representation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CBC mechanism | covered | covered | covered | covered | covered | covered | covered | covered | covered | n/a — mode level, no key lifecycle | covered | covered | covered |
| V1 bit-flipping | covered | covered | covered | covered | covered | covered | covered | covered | covered | n/a | covered | covered | covered |
| V2 padding oracle | covered | covered | covered | covered | covered | **required gap → F-07** (false-positive case omitted) | covered | covered | covered | n/a | covered | covered | covered |
| V3 predictable IV | covered | covered | covered | covered | **required gap → O-02** (`IV_target` undefined) | covered | covered | covered | covered | n/a | covered | covered | covered |
| V4 CBC-R forgery | covered | covered | covered | covered | **required gap → F-04** (IV control) | covered | **required gap → F-04** | covered | covered | n/a | covered | covered | covered |
| AEAD remediation | covered | covered | covered | covered | covered | covered | covered | covered | covered | covered (rekeying) | covered | **required gap → O-01** (EtM/MtE) | optional extension |
| GCM residual risk | covered | covered | covered | covered | covered | covered | **required gap → F-06** (deterministic ceiling) | covered | covered | covered | covered | covered | optional extension |
| Detection guidance | covered | covered | covered | covered | covered | covered | covered | covered | covered | n/a | covered | **required gap → O-01** | optional extension |

## Cross-format and cross-page ledger

| Concept or claim | Representations compared | Result |
| --- | --- | --- |
| CBC-R capability | prose, README bullet, `vector4-cbc-r-forgery.svg`, `ui.mjs` verdict | All four unqualified — F-04; all four now carry the IV prerequisite |
| Padding-oracle validity test | prose, `vector2-padding-oracle.svg`, `attacks.mjs` guard + comment | Code contradicted prose and diagram — F-07; both corrected |
| Query bound `256 × L` | prose, SVG, README, `attacks.mjs` comment, test assertion | Absolute bound not guaranteed — F-07/O-06; softened in all five |
| BEAST citation | prose ×2, Primary references, CD-0001 | Dead URL ×4, wrong venue ×2 — F-05; live content fixed, CD-0001 preserved as history |
| SP 800-38A IV wording | prose, Primary references, CD-0001 | "shall" not the source's word — F-08; corrected |
| Test-suite evidence | footer vs README `test/` bullet | Footer overclaimed — F-10; both now describe the same scope |
| Bit-flip profile string | `attacks.mjs` profile vs `vector1-bit-flipping.svg` header vs `ui.mjs` tag | Diagram said `;comment2=user`; tag said "bits" not bytes — O-04; corrected |
| Diagram semantic colors | all 6 SVGs vs generator docstring | Green meant both "safe" and "attack succeeded" — O-03; one convention now documented and applied |

## Visual content ledger

| Visual | Claims it asserts | Independently correct? | Self-sufficient when detached | Caption and alt text verified | Generator and correspondence check | Standalone defensibility | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `modes-cbc-vs-gcm.svg` | CBC feedback path, GCM tag-verify-before-release, abort branch | Yes | Yes — carries its own scope line | Alt text conveys the conclusion; no caption needed | Re-ran generator; byte-identical | Yes — contrast framing, no targeting content | Closed |
| `taxonomy.svg` | 3 root causes → 4 vectors, attacker-mode labels, edge from root cause 2 → V4 | Yes | Yes — scope line inside | Alt text lists causes and vectors | Byte-identical; stale generator comment O-07 | Yes | Closed; O-07 fixed |
| `vector1-bit-flipping.svg` | Profile string, byte offsets 0 and 5, Δ, scrambled P′[1], forged P′[2] | **No** — profile string and "XOR ':'" wrong; green marked attack success | Yes — scope line inside | Alt text lacked the delta and the scrambled block | Re-ran; matched source | Yes — local service named | **O-03, O-04** — fixed; alt text rewritten |
| `vector2-padding-oracle.svg` | Oracle biconditional, `I[15] = C'[15] ⊕ 0x01`, `≤ 256 × L` | **No** — asserted a false biconditional | Yes — scope line inside | Alt text omitted the false-positive step | Re-ran; matched source | Yes — local mock oracle named | **F-07, O-03** — fixed; alt text rewritten |
| `vector3-predictable-iv.svg` | Chained-IV rule, `P_guess` formula, match condition | Yes, but `IV_target` undefined | Yes — names CVE-2011-3389 and the local session | Alt text lacked the formula | Re-ran; matched source | Yes — "educational simulation" stated | **O-02, O-03** — fixed; alt text rewritten |
| `vector4-cbc-r-forgery.svg` | Backward synthesis steps, `C[n-1] = I[n] ⊕ P[n]`, "100% valid padding" | **No** — omitted the IV prerequisite | Partly — carried scope but not the prerequisite | Alt text omitted the limitation | Re-ran; matched source | Yes — local oracle named | **F-04, O-03** — fixed; alt text rewritten |

Provenance note: at baseline all six committed SVGs were byte-identical to freshly generated output **except for one trailing newline** added by commit `16ade34`, which the generator did not write (O-05). The generator is now idempotent under the repository's `end-of-file-fixer` hook, verified by running it twice and comparing hashes.

### Representation opportunities

| Location | What is dense | Proposed form | Required gap or optional extension |
| --- | --- | --- | --- |
| Vector 3 BEAST alignment | Block alignment as `i` advances past one block is carried entirely by algebra | A block-offset strip showing filler shrinking as recovered bytes fill in | Optional extension — the prose is followable, and this is the exact area where the implementation was wrong (F-02) |
| EtM / MtE / E&M ordering | Three compositions distinguished only in prose | Three-row sequence comparison showing where verification sits relative to unpadding | Optional extension |

## Applicable durable content decisions

| Decision ID | Affected concept | Disposition | Current evidence and rationale |
| --- | --- | --- | --- |
| CD-0001 | 3-root-cause / 4-vector taxonomy, AEAD remediation | **Reopened, then superseded by CD-0002** | Taxonomy itself met no invalidation condition and is reaffirmed inside CD-0002. Two conditions from the guide were met: new primary evidence contradicted the recorded rationale (WOOT 2010 introduces CBC-R as its own contribution, contradicting the record's Vaudenay attribution), and executable artifacts showed the approved outcome did not work (Vectors 2 and 3). Its `verification_methods` also claimed browser-verified rendering and full vector coverage that did not hold. Record preserved unedited as history. |
| CD-0002 | Taxonomy reaffirmed; attributions and demo verification corrected | Created | Supersedes CD-0001. |
| CD-0003 | CBC-R IV-control prerequisite | Created | From F-04. |
| CD-0004 | Padding-oracle validity is block-wide | Created | From F-07. |
| CD-0005 | SP 800-38D IV construction ceilings | Created | From F-06. |
| CD-0006 | Diagram semantic color convention | Created | From O-03. |
| CD-0007 | EtM vs MtE composition coverage | Created | From O-01. |
| CD-0008 | textContent-only demo output | Created | From F-09. |

## Mechanical and rendered checks

| Check | Scope | Result | What this does not prove |
| --- | --- | --- | --- |
| `node --test` | all modules | 7/7 at baseline; **10/10** after remediation | Passing did not imply the browser worked — the baseline suite covered neither the `onProgress` path nor multi-block secrets |
| `npm run lint` | all `.mjs` | Clean before and after | Nothing about factual accuracy or runtime behavior |
| Live browser run | all 5 demos, in-app Chromium, dark scheme, desktop | Baseline: V2 threw, V3 truncated. After: all 5 correct | Not tested in Safari, Firefox, or at mobile widths |
| XSS probe | `bf-user`, `frg-payload` | Baseline: payload executed in the CBC-R sink. After: 0 injected nodes, rendered literally | Covers the sinks reachable from the demo inputs, not a full audit |
| Padding-oracle stress run | 40 randomized recoveries, page default secret, with `onProgress` | 40/40 exact; max 9241 queries for L=64 | Not a proof of the worst-case bound, only evidence against the asserted one |
| BEAST recovery | 4 secrets of 14–25 bytes | Baseline: 3/4 truncated. After: 4/4 exact | — |
| Generator provenance | all 6 SVGs | Re-run and hash-compared; idempotent after O-05 fix | That the figures are conceptually correct — that is the visual ledger's job |
| External link check | 21 URLs at baseline, 21 after | Baseline: 1× 404 (IACR BEAST). After: all live content 200 | That a reachable URL supports the claim beside it |
| Deployed-site hash comparison | 4 files vs GitHub Pages | Identical to baseline | That the deployment stays in sync after the next push |
| `verify_content_decisions.py` | register | Validated 8 decisions | Structure and references only, not technical correctness |

## Open required findings

None. All ten findings from the frozen baseline, plus one found during remediation, are resolved in the working tree.

| ID | Location | Finding | Resolution |
| --- | --- | --- | --- |
| F-01 | `docs/js/attacks.mjs` `recoverPlaintextWithOracle` | Temporal-dead-zone `ReferenceError` whenever `onProgress` was supplied — always, from the UI. Vector 2 recovered nothing on the live site; `ui.mjs` had no `catch`, so it failed silently | Partial state now passed through the callback payload; every demo wrapped in `catch` with a visible failure verdict; regression test added for the callback path |
| F-02 | `docs/js/attacks.mjs` `recoverSecretViaBeast` | Known-context built from request filler instead of recovered bytes, so alignment broke at byte 16. The site's own 25-byte default cookie yielded `SESSION=auth_99a`, then the UI declared success | Known context read from `filler ‖ recovered`; silent `break` replaced with a thrown error; regression tests for 17- and 25-byte secrets and for loud failure |
| F-03 | `index.html` Vector 4; `CONTENT_DECISIONS.yml` | CBC-R credited to Vaudenay 2002, contradicted by the cited WOOT 2010 paper | Attribution corrected in prose with the paper's own wording; CD-0002 records it |
| F-04 | `index.html` Vector 4; `vector4-cbc-r-forgery.svg`; `README.md`; `ui.mjs` | "100% valid PKCS#7" stated with no mention that the endpoint must accept an attacker-supplied IV | Prerequisite callout added; qualifier added to README, SVG, and demo verdict; CD-0003 |
| F-05 | `index.html` ×3; `CONTENT_DECISIONS.yml` | BEAST citation URL returned 404 and was attributed to CRYPTO 2011; it is a 2011 Netifera white paper | Archived original substituted (verified to contain the paper); venue and status corrected in Primary references |
| F-06 | `index.html` residual risk | "96-bit deterministic IVs have no invocation limit" contradicts SP 800-38D §8.3 | Rewritten with §8's 2⁻³² bound and both ceilings, quoting the section; CD-0005 |
| F-07 | `index.html` Vector 2; `vector2-padding-oracle.svg` | "Exactly one value … valid padding 0x01" is false; the repo's own guard disproves it | Callout added explaining the false positive and recheck; diagram corrected; query bound softened; CD-0004 |
| F-08 | `index.html` Vector 3; `CONTENT_DECISIONS.yml` | Bolded "shall be unpredictable" presented as SP 800-38A's wording; the document says "must" | Quoted accurately with a note on the document's keyword usage |
| F-09 | `docs/js/ui.mjs` ×4 sinks | Untrusted decrypted text reached `innerHTML`; a payload executed in the CBC-R sink | `ui.mjs` rebuilt with `createElement`/`textContent` helpers; no `innerHTML` remains; CD-0008. Impact was self-XSS only — no cross-user vector on a static page |
| F-10 | `index.html` footer | "Primitives **and attack logic** verified against NIST test vectors" — NIST vectors cover only the primitive | Footer rewritten to distinguish the two, matching the README |
| F-11 | `docs/js/ui.mjs` padding-oracle progress | **Found during remediation, previously masked by F-01.** Recovery runs byte 15 → 0, but the UI appended bytes in callback order, printing each block reversed (`niF laitnedifnoC…`) | Bytes placed at their true offset with `·` placeholders for positions not yet recovered |

## Optional coverage

| ID | Location | Gap | Disposition |
| --- | --- | --- | --- |
| O-01 | `index.html` detection and fix sections | EtM vs MtE never defined, though detection advice said "add an HMAC" and the table named MtE for Lucky 13 | Addressed — new composition-order subsection citing RFC 7366; CD-0007 |
| O-02 | `index.html` Vector 3; `vector3-predictable-iv.svg` | `IV_target` used and never defined | Addressed — renamed `B_target` and defined in place |
| O-03 | all diagrams | Green meant "safe" in one figure and "attack succeeded" in three others | Addressed — one convention documented in the generator and applied; CD-0006 |
| O-04 | `vector1-bit-flipping.svg`; `ui.mjs` | Profile string mismatched the implementation; "XOR ':'" instead of the delta; "bits" instead of bytes | Addressed |
| O-05 | `generate_diagrams.py` | No trailing newline, so every regeneration fought the `end-of-file-fixer` hook | Addressed — idempotence verified by double run |
| O-06 | `test/attacks.test.mjs` | `queryCount <= 256 * L` not strictly guaranteed once the recheck runs | Addressed — bound widened to `256*L + 2*blocks` with a comment |
| O-07 | `generate_diagrams.py` | Comment claimed a Vector 4 edge that is not drawn | Addressed — comment matches the drawing |
| O-08 | `index.html` residual risk | §8.2.2 random field described as exactly 96 bits; 2⁻³² attributed to §8.3 | Addressed — "at least 96 bits"; bound attributed to §8 |
| O-09 | `index.html` demo hints | No runtime expectation for the two slow demos | Addressed — hints state the expected duration and per-byte cost |

## Limitations and uncertainty

- **Vaudenay EUROCRYPT 2002 full text is paywalled** (Springer returns a 303 to an IdP flow). F-03 rests instead on the Rizzo & Duong WOOT 2010 primary text, which is decisive standing alone ("we are surprised that it was not published before"). The negative claim — that Vaudenay 2002 does not contain CBC-R — is supported by that statement rather than by reading Vaudenay directly.
- **Browser coverage is partial.** Rendered checks ran in the in-app Chromium at the dark color scheme and desktop width only. Safari, Firefox, light scheme, and mobile widths were not exercised.
- **GitHub-side rendering unverified.** Whether `taxonomy.svg`'s `prefers-color-scheme` block survives GitHub's image proxy in the rendered README was not checked in the GitHub UI.
- **Browser timing is environmental.** The padding-oracle demo stalls when the browser pane is hidden (background timer throttling) and resumes when fronted. Correctness was established deterministically in Node instead — 40/40 exact recoveries. The in-browser wall clock measured here should not be read as representative of a normal desktop browser.
- **The worst-case query bound is not proven,** only bounded by observation across 40 runs plus the structure of the recheck.
- **This record covers the frozen baseline.** The remediated state has a different fingerprint and has not itself been through a full fresh review; the closure attestation below applies to `7745a5d6…`, not to the working tree.

## Closure attestation

- [x] Every in-scope artifact was inventoried and read in full.
- [x] Every material claim was entered in the ledger and dispositioned.
- [x] Every topic received a completeness classification for every category.
- [x] Every mandatory pass was completed separately.
- [x] Current primary sources were used for standards-sensitive and time-sensitive claims.
- [x] Prose, metadata, diagrams, captions, alt text, examples, summaries, navigation, and generators were reconciled.
- [x] Every visual was reviewed as its own artifact for independent correctness, detached self-sufficiency, generator provenance, and standalone defensibility, separately from the cross-format pass.
- [x] Applicable mechanical and rendered checks passed or their limitations are recorded.
- [x] Applicable durable content decisions were reconciled after the independent claim review, and every reversal or supersession is justified.
- [x] Residual exhaustion was completed after findings were assembled.
- [x] The baseline remained frozen; remediation ran as a separate phase and its resulting state is identified above.
- [x] Required findings, optional coverage, and limitations are separated.

Closure conclusion: The fresh review of commit `16ade34` (fingerprint `7745a5d6…`) is complete. It found ten required corrections and nine optional gaps; two required findings were functional defects that made advertised demonstrations fail on the live site, and both were invisible to a green test suite. All findings have been remediated in the working tree under an explicit instruction to fix them, and an eleventh defect (F-11), unmasked by the first fix, was found and corrected during that phase. **This record does not close the remediated state.** Confirming that requires a new frozen baseline and repeated passes.

### Note on the preceding record

The previous record in this file declared "Complete with no open findings" at commit `6698eb0` and marked claims C-003, C-005, and C-007 "verified accurate" — all three are contradicted above. The diff `6698eb0..16ade34` touches only trailing newlines in the six SVGs, `LICENSE`, and the review file itself; `docs/index.html`, `docs/js/*.mjs`, `test/`, and `README.md` are unchanged. Every finding recorded here was therefore discoverable at that baseline. Per this standard's own rule, a large set of newly reported, previously discoverable issues on unchanged scope is evidence that the earlier review did not reach the required depth.
