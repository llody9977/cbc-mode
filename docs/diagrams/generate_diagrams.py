"""Generate the theme-aware SVG diagrams embedded in docs/index.html.

The SVGs use CSS variables for theme-dependent colors (cards, backgrounds, borders,
ink, and muted text) with a prefers-color-scheme: dark override. Semantic colors
(navy, danger red, safe green, purple, amber, blue) remain fixed so they read clearly
on both light and dark backgrounds.

Color convention, applied consistently across every diagram: RED marks an attacker-
controlled input or a successful attack outcome, GREEN marks a defense holding, PURPLE
marks an oracle interaction, AMBER marks a leaked or predictable value, NAVY marks a
neutral cipher operation. Green never labels a successful attack.

Run: `python3 docs/diagrams/generate_diagrams.py`
"""
import pathlib

OUT = pathlib.Path(__file__).resolve().parent
OUT.mkdir(parents=True, exist_ok=True)

SANS = "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

# Sentinels mapped to theme-aware CSS classes
INK, MUTED, NEU_F, NEU_S = "@ink", "@muted", "@neuf", "@neus"
ARROW = "@arw"

# Fixed semantic colors
NAVY = "#1f3a5f"
RED, GREEN, PURPLE, AMBER, GRAY, BLUE = "#dc2626", "#16a34a", "#6d28d9", "#b45309", "#64748b", "#2563eb"

STYLE = (
    '<style>'
    ':root{--card:#ffffff;--panel:#f8fafc;--border:#e2e8f0;--ink:#0f172a;--muted:#475569;'
    '--neuf:#f1f5f9;--neus:#cbd5e1;--arw:#94a3b8}'
    '@media (prefers-color-scheme:dark){:root{--card:#0d1117;--panel:#161b22;--border:#30363d;'
    '--ink:#e6edf3;--muted:#9aa4b2;--neuf:#1c2330;--neus:#3d444d;--arw:#6e7681}}'
    '.cardb{fill:var(--card);stroke:var(--border)}.card{fill:var(--card)}'
    '.panel{fill:var(--panel);stroke:var(--border)}'
    '.neu{fill:var(--neuf);stroke:var(--neus)}.cellA{fill:var(--neuf);stroke:var(--neus)}'
    '.xor{fill:var(--card);stroke:var(--muted)}'
    '.ink{fill:var(--ink)}.muted{fill:var(--muted)}'
    '.arw{stroke:var(--arw)}.arwhead{fill:var(--arw)}'
    '</style>'
)

def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _fillattr(color):
    return {INK: 'class="ink"', MUTED: 'class="muted"'}.get(color, f'fill="{color}"')

def text(x, y, s, size=13, fill=INK, anchor="middle", weight="400", mono=False, lh=15):
    font = MONO if mono else SANS
    lines = s.split("\n")
    parts = [f'<text x="{x}" y="{y}" font-family="{font}" font-size="{size}" {_fillattr(fill)} '
             f'text-anchor="{anchor}" font-weight="{weight}">']
    for i, ln in enumerate(lines):
        parts.append(f'<tspan x="{x}" dy="{0 if i == 0 else lh}">{esc(ln)}</tspan>')
    parts.append('</text>')
    return "".join(parts)

def box(x, y, w, h, label, fill=NEU_F, stroke=NEU_S, tc=INK, mono=False, rx=9, size=13, weight="600", lh=15, sw=1.5):
    n = len(label.split("\n"))
    cx, cy = x + w / 2, y + h / 2
    first = cy - (n - 1) * lh / 2 + size / 3
    if fill == NEU_F and stroke == NEU_S:
        rect = f'<rect class="neu" x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" stroke-width="{sw}"/>'
    else:
        rect = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>'
    return rect + text(cx, first, label, size=size, fill=tc, mono=mono, weight=weight, lh=lh)

def arrow(x1, y1, x2, y2, dashed=False, color=ARROW, sw=2):
    da = ' stroke-dasharray="6 5"' if dashed else ''
    st = 'class="arw"' if color == ARROW else f'stroke="{color}"'
    return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" {st} stroke-width="{sw}"{da} marker-end="url(#arw)"/>'

def path(d, dashed=False, color=ARROW, sw=2):
    da = ' stroke-dasharray="6 5"' if dashed else ''
    st = 'class="arw"' if color == ARROW else f'stroke="{color}"'
    return f'<path d="{d}" fill="none" {st} stroke-width="{sw}"{da} marker-end="url(#arw)"/>'

def alabel(x, y, s, size=11, fill=MUTED):
    w = len(s) * size * 0.56 + 10
    return (f'<rect class="card" x="{x - w / 2}" y="{y - size + 2}" width="{w}" height="{size + 6}" rx="4" opacity="0.95"/>'
            + text(x, y + 3, s, size=size, fill=fill, weight="500"))

def svg(w, h, title, body, subtitle=None):
    head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" font-family="{SANS}">'
            + STYLE
            + '<defs><marker id="arw" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto" markerUnits="strokeWidth">'
            + '<path d="M0,0 L8,3 L0,6 z" class="arwhead"/></marker></defs>'
            + f'<rect class="cardb" x="1" y="1" width="{w - 2}" height="{h - 2}" rx="14" stroke-width="2"/>'
            + text(w / 2, 32, title, size=17, fill=INK, weight="700"))
    if subtitle:
        head += text(w / 2, 52, subtitle, size=12, fill=MUTED)
    return head + body + '</svg>'

W = 900

def panel(x, y, w, h):
    return f'<rect class="panel" x="{x}" y="{y}" width="{w}" height="{h}" rx="10" stroke-width="1.5"/>'

# ---------------- Diagram 1: CBC Decryption Malleability vs GCM ----------------
def d1():
    b = [text(W / 2, 76, "Decryption data-flow: CBC's unauthenticated feedback vs GCM's authenticated check", size=13, fill=MUTED)]

    # Left: AES-CBC Decryption
    b.append(panel(30, 96, 400, 240))
    b.append(text(230, 122, "AES-CBC Decryption (Malleable)", size=14, fill=RED, weight="700"))
    b.append(box(60, 145, 140, 36, "Ciphertext C[i-1]", fill="#fee2e2", stroke=RED, tc="#991b1b", size=12))
    b.append(box(250, 145, 140, 36, "Ciphertext C[i]", fill="#f1f5f9", stroke=NEU_S, tc=INK, size=12))
    b.append(box(250, 210, 140, 36, "AES Decrypt D_K(·)", fill=NAVY, stroke="#0d1b2a", tc="#fff", size=12))
    b.append(arrow(320, 181, 320, 210))
    b.append(box(160, 266, 140, 36, "Plaintext P[i]", fill="#fee2e2", stroke=RED, tc="#991b1b", size=12))
    # XOR link
    b.append(path("M 130 181 L 130 250 L 210 250 L 210 266", color=RED))
    b.append(arrow(320, 246, 250, 266))
    b.append(alabel(130, 215, "flip bit in C[i-1]", fill=RED))
    b.append(alabel(230, 284, "P[i] bit flips cleanly!", fill=RED))

    # Right: AES-GCM
    b.append(panel(470, 96, 400, 240))
    b.append(text(670, 122, "AES-GCM (Authenticated)", size=14, fill=GREEN, weight="700"))
    b.append(box(500, 145, 150, 36, "Ciphertext C", fill="#f1f5f9", stroke=NEU_S, tc=INK, size=12))
    b.append(box(690, 145, 150, 36, "Auth Tag T", fill="#dcfce7", stroke=GREEN, tc="#166534", size=12))
    b.append(box(500, 205, 340, 36, "Verify GHASH Tag T == T_computed?", fill=NAVY, stroke="#0d1b2a", tc="#fff", size=12))
    b.append(arrow(575, 181, 575, 205))
    b.append(arrow(765, 181, 765, 205))
    b.append(box(500, 266, 340, 36, "Valid → Emit Plaintext | Tampered → Abort", fill="#dcfce7", stroke=GREEN, tc="#166534", size=12))
    b.append(arrow(670, 241, 670, 266))

    b.append(text(W / 2, 358, "Scope: educational analysis of CBC mode vulnerabilities; all mechanisms verified against real Web Crypto AES.",
                  size=10.5, fill=MUTED))
    return svg(W, 376, "AES-CBC Malleability vs AES-GCM Authenticated Encryption", "".join(b))

# ---------------- Diagram 2: Taxonomy ----------------
def d2():
    b = [box(W / 2 - 80, 62, 160, 44, "AES-CBC", fill=NAVY, stroke="#0d1b2a", tc="#fff", size=15, weight="700")]
    r1 = (40, 145, 250, 68)
    r2 = (325, 145, 250, 68)
    r3 = (610, 145, 250, 68)

    b.append(box(*r1, "Root cause 1 — No integrity\nCiphertext is malleable; modifying C[i-1]\nmutates P[i] deterministically",
                 fill=NAVY, stroke="#0d1b2a", tc="#fff", size=11.5))
    b.append(box(*r2, "Root cause 2 — Padding oracle\nUnauthenticated decryption leaks 1-bit\nPKCS#7 padding validation status",
                 fill=NAVY, stroke="#0d1b2a", tc="#fff", size=11.5))
    b.append(box(*r3, "Root cause 3 — Predictable IV\nUsing chained/predictable IVs breaks\nIND-CPA indistinguishability",
                 fill=NAVY, stroke="#0d1b2a", tc="#fff", size=11.5))

    b.append(arrow(W / 2 - 20, 106, r1[0] + r1[2] / 2, r1[1] - 2))
    b.append(arrow(W / 2, 106, r2[0] + r2[2] / 2, r2[1] - 2))
    b.append(arrow(W / 2 + 20, 106, r3[0] + r3[2] / 2, r3[1] - 2))

    vy, vh = 264, 68
    vs = [
        (30, 195, "Vector 1", "Bit-flipping malleability", "active mutation", RED),
        (245, 195, "Vector 2", "Padding oracle decryption", "active oracle (Vaudenay)", RED),
        (460, 195, "Vector 3", "Predictable IV attack", "chosen plaintext (BEAST)", AMBER),
        (675, 195, "Vector 4", "Padding oracle forgery", "active synthesis (CBC-R)", PURPLE),
    ]
    for x, w, vt, desc, mode, ac in vs:
        b.append(f'<rect class="neu" x="{x}" y="{vy}" width="{w}" height="{vh}" rx="9" stroke-width="1.5"/>')
        b.append(f'<rect x="{x}" y="{vy}" width="6" height="{vh}" rx="3" fill="{ac}"/>')
        cx = x + w / 2
        b.append(text(cx, vy + 22, vt, size=13, fill=INK, weight="700"))
        b.append(text(cx, vy + 40, desc, size=11.5, fill=INK))
        b.append(text(cx, vy + 56, mode, size=10.5, fill=MUTED, weight="500"))

    # Connections to vectors
    b.append(arrow(r1[0] + r1[2] / 2, r1[1] + r1[3], vs[0][0] + vs[0][1] / 2, vy - 2))
    b.append(arrow(r2[0] + r2[2] / 2, r2[1] + r2[3], vs[1][0] + vs[1][1] / 2, vy - 2))
    b.append(arrow(r3[0] + r3[2] / 2, r3[1] + r3[3], vs[2][0] + vs[2][1] / 2, vy - 2))
    # Only the root-cause-2 edge is drawn: the padding oracle is what supplies D_K.
    # Vector 4 also rests on root cause 1, which the Vector 4 prose states.
    b.append(arrow(r2[0] + r2[2] / 2, r2[1] + r2[3], vs[3][0] + vs[3][1] / 2, vy - 2))

    b.append(text(W / 2, 362, "Scope: educational analysis of CBC mode vulnerabilities; all attacks demonstrated against self-contained local oracles.",
                  size=10.5, fill=MUTED))
    return svg(W, 378, "CBC mode's three root causes and four attack vectors", "".join(b),
               subtitle="structural flaws in unauthenticated CBC mode and their attack manifestations")

# ---------------- Diagram 3: Vector 1 Bit-Flipping ----------------
def d3():
    b = [box(40, 62, W - 80, 40, "Target profile: comment1=preview;userdata_input=[:role<admin];comment2=standard_user;role=user",
             fill=NAVY, stroke="#0d1b2a", tc="#fff", size=13)]

    b.append(panel(40, 120, W - 80, 260))
    b.append(text(60, 146, "1. Normal Token Issued by Server", size=13, fill=INK, weight="700", anchor="start"))

    cw = 48
    # Show Block 1 (ciphertext bytes) and Block 2 (plaintext bytes)
    b.append(text(60, 180, "Ciphertext Block 1 (preceding block):", size=12, fill=MUTED, anchor="start"))
    b.append(box(60, 195, 360, 36, "C[1] (bytes 16..31)", fill=NEU_F, stroke=NEU_S, tc=INK, size=12))
    b.append(box(440, 195, 360, 36, "C[2] (bytes 32..47)", fill=NEU_F, stroke=NEU_S, tc=INK, size=12))

    b.append(text(60, 260, "2. Attacker XORs C[1] bytes 0 and 5 with Δ = 0x01 (':'⊕';' and '<'⊕'='):", size=13, fill=RED, weight="700", anchor="start"))
    b.append(box(60, 280, 360, 36, "C'[1] = C[1] ⊕ Δ (tampered)", fill="#fee2e2", stroke=RED, tc="#991b1b", size=12))
    b.append(box(440, 280, 360, 36, "C[2] (unchanged)", fill=NEU_F, stroke=NEU_S, tc=INK, size=12))

    b.append(arrow(240, 316, 240, 345))
    b.append(arrow(620, 316, 620, 345))

    b.append(box(60, 345, 360, 36, "P'[1] = Scrambled garbage", fill="#f1f5f9", stroke=GRAY, tc=MUTED, size=12))
    b.append(box(440, 345, 360, 36, "P'[2] starts ';role=admin;' — FORGED ROLE", fill="#fee2e2", stroke=RED, tc="#991b1b", size=12, weight="700"))

    b.append(text(W / 2, 405, "Scope: demonstrated on local ProfileCookieService; no knowledge of secret key required.",
                  size=10.5, fill=MUTED))
    return svg(W, 420, "Vector 1 — CBC Bit-Flipping Malleability", "".join(b))

# ---------------- Diagram 4: Vector 2 Padding Oracle Decryption ----------------
def d4():
    b = [box(40, 62, W - 80, 40, "Padding Oracle: returns True if decrypted plaintext has valid PKCS#7 padding",
             fill=NAVY, stroke="#0d1b2a", tc="#fff", size=13)]

    b.append(panel(40, 116, W - 80, 220))
    b.append(text(60, 140, "Iterative byte recovery from byte 15 down to 0:", size=13, fill=INK, weight="700", anchor="start"))

    b.append(box(60, 160, 360, 40, "Craft probe block C' with candidate byte at position 15\nTarget padding: 0x01", fill=NEU_F, stroke=NEU_S, tc=INK, size=11.5))
    b.append(arrow(420, 180, 470, 180))
    b.append(box(470, 160, 370, 56, "Oracle returns True for ANY valid PKCS#7 ending\nOne candidate gives 0x01 → I[15] = C'[15] ⊕ 0x01\n(recheck byte 14 to reject 0x02 0x02 …)", fill="#ede9fe", stroke=PURPLE, tc="#5b21b6", size=11.5))

    b.append(arrow(655, 216, 655, 238))
    b.append(box(470, 238, 370, 40, "Set C'[15] = I[15] ⊕ 0x02, test C'[14] for padding 0x02\nReveals intermediate byte I[14] = C'[14] ⊕ 0x02", fill="#ede9fe", stroke=PURPLE, tc="#5b21b6", size=11.5))
    b.append(arrow(470, 258, 420, 258))
    b.append(box(60, 238, 360, 40, "Compute Plaintext: P[i] = I ⊕ C[i-1]\nQueries: ≈ 256 × L worst case (avg ≈ 128 × L)", fill="#fee2e2", stroke=RED, tc="#991b1b", size=12, weight="700"))

    b.append(text(W / 2, 360, "Scope: demonstrated against local mock oracle (makePaddingOracle); key never exposed.",
                  size=10.5, fill=MUTED))
    return svg(W, 376, "Vector 2 — Vaudenay Padding Oracle Plaintext Recovery", "".join(b))

# ---------------- Diagram 5: Vector 3 BEAST Predictable IV ----------------
def d5():
    b = [box(40, 62, W - 80, 40, "TLS 1.0 Chained IV Vulnerability: Record N+1 uses Record N's last ciphertext block as IV",
             fill=NAVY, stroke="#0d1b2a", tc="#fff", size=13)]

    b.append(panel(40, 116, W - 80, 230))
    b.append(text(60, 140, "Chosen-Plaintext Guess Alignment (BEAST):", size=13, fill=INK, weight="700", anchor="start"))

    b.append(box(60, 160, 370, 44, "1. Target Request (Record N):\nCapture C_target = E_K(IV_target ⊕ (Pad ‖ Secret))", fill=NEU_F, stroke=NEU_S, tc=INK, size=11.5))
    b.append(box(470, 160, 370, 44, "2. Predictable Next IV:\nAttacker knows IV_next = C_last", fill="#fef3c7", stroke=AMBER, tc="#92400e", size=11.5))

    b.append(arrow(245, 204, 245, 230))
    b.append(arrow(655, 204, 655, 230))

    b.append(box(60, 230, 780, 50, "3. Probe Request (Record N+1): Attacker submits P_guess = IV_next ⊕ IV_target ⊕ (Pad ‖ Candidate)\nCipher computes: E_K(P_guess ⊕ IV_next) = E_K(IV_target ⊕ (Pad ‖ Candidate))\nWhen C_probe == C_target → Candidate is the exact secret byte!",
                 fill="#fee2e2", stroke=RED, tc="#991b1b", size=12, weight="600"))

    b.append(text(W / 2, 368, "Scope: educational simulation of CVE-2011-3389 against local ChainedIvSession.",
                  size=10.5, fill=MUTED))
    return svg(W, 384, "Vector 3 — Predictable IV Chosen-Plaintext Attack (BEAST)", "".join(b))

# ---------------- Diagram 6: Vector 4 CBC-R Forgery ----------------
def d6():
    b = [box(40, 62, W - 80, 40, "CBC-R Forgery: valid ciphertext for a chosen plaintext, from a padding oracle alone (no key)",
             fill=NAVY, stroke="#0d1b2a", tc="#fff", size=13)]

    b.append(panel(40, 116, W - 80, 230))
    b.append(text(60, 140, "Backwards Ciphertext Block Synthesis:", size=13, fill=INK, weight="700", anchor="start"))

    b.append(box(60, 160, 240, 44, "1. Pick Random C[n]\nLast ciphertext block", fill=NEU_F, stroke=NEU_S, tc=INK, size=11.5))
    b.append(arrow(300, 182, 340, 182))
    b.append(box(340, 160, 240, 44, "2. Oracle recovers I[n]\nI[n] = D_K(C[n])", fill="#ede9fe", stroke=PURPLE, tc="#5b21b6", size=11.5))
    b.append(arrow(580, 182, 620, 182))
    b.append(box(620, 160, 220, 44, "3. Compute C[n-1]\nC[n-1] = I[n] ⊕ P[n]", fill="#fef3c7", stroke=AMBER, tc="#92400e", size=11.5))

    b.append(arrow(730, 204, 730, 230))
    b.append(box(60, 230, 780, 62, "4. Repeat backwards for C[n-2]... down to IV = I[1] ⊕ P[1]\nResult: (IV, C[1], ..., C[n]) decrypts to the chosen plaintext, valid PKCS#7\nREQUIRES the endpoint to accept an attacker-supplied IV, else block 1 is garbage",
                 fill="#fee2e2", stroke=RED, tc="#991b1b", size=12, weight="700"))

    b.append(text(W / 2, 368, "Scope: demonstrated using local makePaddingOracle and forgeCiphertextWithOracle.",
                  size=10.5, fill=MUTED))
    return svg(W, 384, "Vector 4 — CBC Padding Oracle Ciphertext Forgery (CBC-R)", "".join(b))

def main():
    diagrams = {
        "modes-cbc-vs-gcm.svg": d1(),
        "taxonomy.svg": d2(),
        "vector1-bit-flipping.svg": d3(),
        "vector2-padding-oracle.svg": d4(),
        "vector3-predictable-iv.svg": d5(),
        "vector4-cbc-r-forgery.svg": d6(),
    }
    for filename, content in diagrams.items():
        path = OUT / filename
        # Trailing newline keeps regeneration idempotent under the repo's
        # pre-commit end-of-file-fixer hook.
        path.write_text(content + "\n", encoding="utf-8")
        print(f"Generated: {path}")

if __name__ == "__main__":
    main()
