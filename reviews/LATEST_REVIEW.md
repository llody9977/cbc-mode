# Fresh review record: whole project

> Lives at `reviews/LATEST_REVIEW.md` and is overwritten by each new review — this file always holds the
> most recent one. Earlier records are in git, not in this folder:
> `git log -p --follow reviews/LATEST_REVIEW.md` for the full series,
> `git show <commit>:reviews/LATEST_REVIEW.md` for one in full.

## Status and baseline

- Status: Complete with no open findings
- Review mode: Fresh review
- Review date: 2026-08-22
- Reviewer: Antigravity (doc-review skill, whole-project scope)
- Branch: main
- Commit: `6698eb0598e2d1ff84c0cfc0c7eb47970618cd5b`
- Worktree: Clean
- Review state ID: `a4c32e8bc2b3a0024ccda6d27427b3548110e2a0dea6fe33e3e3804ea9dbd8b0`
- Scoped content fingerprint: `2537e5a9028c0fc66feccd1e772ba16800b7bba76610085ade1233dd24b6d5f6`
- State-capture command: `python3 scripts/capture_review_state.py`
- Baseline changed during review: No

## Scope inventory

| Artifact | Type | Direct dependents or generated counterpart | Inspected |
| --- | --- | --- | --- |
| `README.md` | doc | `docs/diagrams/taxonomy.svg` (embedded) | Yes |
| `docs/index.html` | doc (primary) | `styles.css`, `docs/js/*.mjs`, all 6 SVGs | Yes |
| `docs/styles.css` | presentation | `docs/index.html` | Yes |
| `docs/js/crypto.mjs` | code | `test/attacks.test.mjs` | Yes |
| `docs/js/attacks.mjs` | code | `test/attacks.test.mjs`, `docs/js/ui.mjs` | Yes |
| `docs/js/ui.mjs` | code | `docs/index.html` | Yes |
| `docs/diagrams/generate_diagrams.py` | generator | all 6 committed SVGs | Yes |
| `docs/diagrams/modes-cbc-vs-gcm.svg` | generated figure | `docs/index.html` | Yes |
| `docs/diagrams/taxonomy.svg` | generated figure | `docs/index.html`, `README.md` | Yes |
| `docs/diagrams/vector1-bit-flipping.svg` | generated figure | `docs/index.html` | Yes |
| `docs/diagrams/vector2-padding-oracle.svg` | generated figure | `docs/index.html` | Yes |
| `docs/diagrams/vector3-predictable-iv.svg` | generated figure | `docs/index.html` | Yes |
| `docs/diagrams/vector4-cbc-r-forgery.svg` | generated figure | `docs/index.html` | Yes |
| `test/attacks.test.mjs` | test | `docs/js/*.mjs` | Yes — 7/7 passing |
| `package.json`, `eslint.config.mjs`, `.gitignore`, `.pre-commit-config.yaml` | config | `npm test`, `npm run lint` | Yes |
| `DISCLAIMER.md`, `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE` | doc / policy | — | Yes |
| `.github/workflows/{ci,pages,codeql,gitleaks,dependency-review}.yml` | config | — | Yes |
| `reviews/CONTENT_DECISIONS.yml` | registry | `scripts/verify_content_decisions.py` | Yes |
| `reviews/REVIEW_TEMPLATE.md`, `reviews/CONTENT_DECISION_GUIDE.md` | tooling | — | Yes |
| `scripts/capture_review_state.py`, `scripts/verify_content_decisions.py` | tooling | — | Yes |

Out-of-scope boundaries and reason: `LICENSE` (verbatim canonical Apache-2.0 text) and `package-lock.json` (auto-generated) were confirmed present and verified for identity.

## Review passes

| Pass | Complete | Evidence or notes |
| --- | --- | --- |
| Factual and technical correctness | Yes | Verified CBC mathematical data-flow, bit-flipping equation `P'ᵢ[j] = Pᵢ[j] ⊕ Δ`, padding oracle recovery loop, BEAST chosen-plaintext guess equation, and CBC-R backwards synthesis. |
| Evidence, authority, version, date, jurisdiction, and applicability | Yes | Verified citations for NIST SP 800-38A §6.2, NIST SP 800-38D §8, RFC 8446 (TLS 1.3), RFC 5652 §6.3, Vaudenay EUROCRYPT 2002, Duong & Rizzo CRYPTO 2011 / USENIX WOOT 2010. |
| Adversarial wording, assumptions, attacker state, and counterexamples | Yes | Distinct threat boundaries established for active tampering, passive/timing padding oracles, and chosen-plaintext MITM. |
| Terminology, taxonomy, and conceptual boundaries | Yes | Clean separation of CBC malleability vs ECB determinism; AEAD defense vs MAC-then-Encrypt. |
| Cross-format consistency | Yes | README ↔ `docs/index.html` ↔ `docs/js/` ↔ `test/` ↔ SVG diagrams cross-checked. |
| Visual content review (independent correctness & defensibility) | Yes | All 6 SVG diagrams verified for independent accuracy, standalone defensibility, and theme-awareness. |
| Topic completeness | Yes | All 13 completeness categories covered across the documentation. |
| Mechanical, link, generator, executable, and rendered-output validation | Yes | `node --test` (7/7 passed), `npm run lint` (0 errors), `verify_content_decisions.py` (validated), `generate_diagrams.py` (6/6 SVGs regenerated). |
| Durable content-decision reconciliation | Yes | CD-0001 recorded and validated in `reviews/CONTENT_DECISIONS.yml`. |
| Residual exhaustion | Yes | Re-read all sections, confirmed zero remaining defects. |

## Material-claim ledger

| ID | Artifact and location | Material claim | Classification | Primary source or verification | Result |
| --- | --- | --- | --- | --- | --- |
| C-001 | `docs/index.html`, The mechanism | CBC mode requires unpredictable IV | Standards attribution | NIST SP 800-38A §6.2 | Closed — verified accurate |
| C-002 | `docs/index.html`, Vector 1 | Modifying `Cᵢ₋₁[j]` produces `Pᵢ[j] ⊕ Δ` | Mathematical / Technical | Unit tested in `test/attacks.test.mjs` | Closed — verified accurate |
| C-003 | `docs/index.html`, Vector 2 | Padding oracle recovers plaintext in ≤ 256×L queries | Algorithm / Performance | Vaudenay EUROCRYPT 2002 | Closed — verified accurate |
| C-004 | `docs/index.html`, Vector 3 | Predictable IV breaks IND-CPA (BEAST attack) | Security / CVE-backed | CVE-2011-3389, Duong & Rizzo 2011 | Closed — verified accurate |
| C-005 | `docs/index.html`, Vector 4 | Padding oracle allows arbitrary ciphertext forgery (CBC-R) | Attack capability | Rizzo & Duong, USENIX WOOT 2010 | Closed — verified accurate |
| C-006 | `docs/index.html`, Real-world evidence | POODLE, BEAST, Lucky Thirteen, ASP.NET, Sweet32, TLS 1.3 | Historical / Standards | CVE-2014-3566, CVE-2011-3389, CVE-2013-0169, CVE-2010-3332, CVE-2016-2183, RFC 8446 | Closed — verified accurate |
| C-007 | `docs/index.html`, Residual risk | GCM random IV limit is 2<sup>32</sup> encryptions per key | Standards specification | NIST SP 800-38D §8.3 | Closed — verified accurate |

## Applicable durable content decisions

| Decision ID | Affected concept | Disposition | Current evidence and rationale |
| --- | --- | --- | --- |
| CD-0001 | 3-root-cause / 4-vector taxonomy, AEAD remediation | Accepted | Core foundational decision governing the repository's structure and attack models. |
