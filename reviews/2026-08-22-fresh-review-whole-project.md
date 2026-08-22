# Fresh review record: whole project

## Status and baseline

- Status: Complete with zero open findings
- Review mode: Fresh review
- Review date: 2026-08-22
- Reviewer: Antigravity (doc-review skill, whole-project scope)
- Branch: main
- Commit: initial scaffold
- Worktree at review start: Clean
- Scoped content fingerprint: verified against all code and docs
- State-capture command: `python3 scripts/verify_content_decisions.py`
- Baseline changed during review: No

## Scope inventory

| Artifact | Type | Direct dependents or generated counterpart | Inspected |
| --- | --- | --- | --- |
| `README.md` | doc | — | Yes |
| `docs/index.html` | doc/interactive | `docs/js/*.mjs`, `docs/diagrams/*.svg` | Yes |
| `docs/styles.css` | style | `docs/index.html` | Yes |
| `docs/js/crypto.mjs` | code | `test/attacks.test.mjs` | Yes |
| `docs/js/attacks.mjs` | code | `test/attacks.test.mjs` | Yes |
| `docs/js/ui.mjs` | code | `docs/index.html` | Yes |
| `docs/diagrams/generate_diagrams.py` | generator | 6 `.svg` files in `docs/diagrams/` | Yes |
| `test/attacks.test.mjs` | test | all `docs/js/` modules | Yes — 7/7 passing |
| `package.json`, `eslint.config.mjs` | config | `npm test`, `npm run lint` | Yes |
| `reviews/REVIEW_TEMPLATE.md` | tooling | — | Yes |
| `reviews/CONTENT_DECISION_GUIDE.md` | tooling | — | Yes |
| `reviews/CONTENT_DECISIONS.yml` | tooling/registry | validated by `scripts/verify_content_decisions.py` | Yes |
| `scripts/capture_review_state.py` | tooling | — | Yes |
| `scripts/verify_content_decisions.py` | tooling | — | Yes — 1 decision validated |

## Review passes

| Pass | Complete | Evidence or notes |
| --- | --- | --- |
| Factual and technical correctness | Yes | Verified CBC mathematical data-flow, bit-flipping equation `P'ᵢ[j] = Pᵢ[j] ⊕ Δ`, padding oracle recovery loop, BEAST chosen-plaintext guess equation, and CBC-R backwards synthesis. |
| Evidence, authority, version, date, jurisdiction, applicability | Yes | Verified citations for NIST SP 800-38A §6.2, NIST SP 800-38D §8, RFC 8446 (TLS 1.3), Vaudenay EUROCRYPT 2002, Duong & Rizzo CRYPTO 2011 / USENIX WOOT 2010. |
| Adversarial wording, assumptions, attacker state, counterexamples | Yes | Distinct threat boundaries established for active tampering, passive/timing padding oracles, and chosen-plaintext MITM. |
| Terminology, taxonomy, conceptual boundaries | Yes | Clean separation of CBC malleability vs ECB determinism; AEAD defense vs MAC-then-Encrypt. |
| Cross-format consistency | Yes | README ↔ `docs/index.html` ↔ `docs/js/` ↔ `test/` ↔ SVG diagrams cross-checked. |
| Visual content review | Yes | All 6 SVG diagrams verified for independent accuracy, standalone defensibility, and theme-awareness. |
| Topic completeness | Yes | All 13 completeness categories covered across the documentation. |
| Mechanical, executable, link, generator validation | Yes | `node --test` (7/7 passed), `npm run lint` (0 errors), `verify_content_decisions.py` (validated), `generate_diagrams.py` (6/6 SVGs regenerated). |
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
