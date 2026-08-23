// Interactive UI controllers for the CBC mode weakness demonstrations.
// Wires browser DOM events to the crypto and attack functions in attacks.mjs and crypto.mjs.
//
// Output discipline: every value rendered below can carry attacker-chosen bytes, because the
// demo inputs flow through real encryption and come back out as decrypted text. Values are
// therefore only ever assigned through textContent, never innerHTML — a payload such as
// `<img src=q onerror=...>` renders as literal characters instead of executing. This file
// uses no innerHTML at all, which is the same rule the page recommends for any untrusted
// value that reaches a DOM sink.

import {
  BLOCK_SIZE, toHex, utf8, utf8Decode, latin1Decode,
  randomKey, randomIv, aesCbcEncrypt, aesCbcDecrypt,
} from "./crypto.mjs";

import {
  ProfileCookieService, forgeAdminViaBitFlip,
  makePaddingOracle, recoverPlaintextWithOracle,
  ChainedIvSession, recoverSecretViaBeast,
  forgeCiphertextWithOracle, gcmTokenRoundtrip,
} from "./attacks.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ---- safe DOM helpers ----
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// A labelled result block. `value` is untrusted and lands in textContent.
function block({ className = "blk", label, value, valueClass = "blk-hex", tag, spaced = false }) {
  const wrap = el("div", className);
  if (spaced) wrap.style.marginTop = "8px";
  wrap.append(el("div", "blk-label", label), el("div", valueClass, value));
  if (tag) wrap.append(el("div", "blk-tag", tag));
  return wrap;
}

function replace(container, ...nodes) {
  container.replaceChildren(...nodes);
}

// Verdict banner. Parts are plain strings or elements; nothing is parsed as markup.
function setVerdict(div, tone, ...parts) {
  div.className = `verdict show ${tone}`;
  replace(div, ...parts.map((p) => (typeof p === "string" ? document.createTextNode(p) : p)));
}

function clearVerdict(div) {
  div.className = "verdict";
  replace(div);
}

function bold(text) {
  return el("strong", null, text);
}

// Streaming recovery box: recovered text plus a blinking cursor.
function renderRecovered(box, text) {
  replace(box, el("span", null, text), el("span", "cursor", "_"));
}

function reportFailure(statusEl, verdictDiv, error) {
  console.error(error);
  if (statusEl) statusEl.textContent = "Failed.";
  setVerdict(verdictDiv, "bad", "⚠️ ", bold("Demonstration failed: "), String(error && error.message ? error.message : error));
}

// ===========================================================================
// DEMO 1: Vector 1 — Bit-Flipping Playground
// ===========================================================================
function initBitFlipDemo() {
  const service = new ProfileCookieService();

  const btnIssue = document.getElementById("bf-issue");
  const btnFlip = document.getElementById("bf-flip");
  const outDiv = document.getElementById("bf-out");
  const verdictDiv = document.getElementById("bf-verdict");
  const userInput = document.getElementById("bf-user");

  if (!btnIssue) return;

  btnIssue.addEventListener("click", async () => {
    btnIssue.disabled = true;
    try {
      const val = userInput.value || ":role<admin";
      const token = await service.issueToken(val);
      const check = await service.verifyToken(token.iv, token.ciphertext);

      replace(outDiv,
        block({ label: "IV (16 bytes hex)", value: toHex(token.iv) }),
        block({ label: `Ciphertext (${token.ciphertext.length} bytes)`, value: toHex(token.ciphertext) }),
        block({ label: "Decrypted Plaintext on Server", value: check.text, valueClass: "tok", spaced: true }),
      );

      setVerdict(verdictDiv, check.isAdmin ? "bad" : "good",
        "Server evaluated: ", bold(`role=${check.isAdmin ? "ADMIN" : "USER"}`),
        ` (Access ${check.isAdmin ? "GRANTED" : "standard user"})`);
      btnFlip.disabled = false;
    } catch (error) {
      reportFailure(null, verdictDiv, error);
    } finally {
      btnIssue.disabled = false;
    }
  });

  btnFlip.addEventListener("click", async () => {
    btnFlip.disabled = true;
    try {
      const forged = await forgeAdminViaBitFlip(service);
      const check = await service.verifyToken(forged.iv, forged.ciphertext);

      replace(outDiv,
        block({
          className: "blk tampered",
          label: "Ciphertext (Block 1 modified with Δ)",
          value: toHex(forged.ciphertext),
          tag: "Bytes 0 and 5 of Block 1 XORed with Δ = 0x01",
        }),
        block({
          label: "Decrypted Plaintext on Server (Note scrambled Block 1, but Block 2 contains role=admin)",
          value: check.text,
          valueClass: "tok",
          spaced: true,
        }),
      );

      setVerdict(verdictDiv, "bad",
        "🚨 Privilege Escalation! Server decrypted role=admin without integrity errors. ",
        bold("Access GRANTED as ADMIN."));
    } catch (error) {
      reportFailure(null, verdictDiv, error);
    } finally {
      btnFlip.disabled = false;
    }
  });
}

// ===========================================================================
// DEMO 2: Vector 2 — Padding Oracle Decryption
// ===========================================================================
function initPaddingOracleDemo() {
  const btnRun = document.getElementById("orc-run");
  const secretIn = document.getElementById("orc-secret");
  const statusSpan = document.getElementById("orc-status");
  const recoveredBox = document.getElementById("orc-recovered");
  const verdictDiv = document.getElementById("orc-verdict");

  if (!btnRun) return;

  btnRun.addEventListener("click", async () => {
    btnRun.disabled = true;
    clearVerdict(verdictDiv);
    renderRecovered(recoveredBox, "");
    statusSpan.textContent = "Initializing oracle and encrypting secret...";

    try {
      const key = randomKey();
      const iv = randomIv();
      const secret = secretIn.value || "Confidential Financial Data: $50,000 to Account 9876";
      const { ciphertext } = await aesCbcEncrypt(key, utf8(secret), iv, true);

      const oracle = makePaddingOracle(key);
      // Bytes come back from position 15 down to 0 within each block, so they are placed
      // at their true offset rather than appended — appending would print each block
      // backwards. Positions not yet recovered show as a placeholder.
      const known = new Array(ciphertext.length).fill("·");

      const result = await recoverPlaintextWithOracle(oracle, iv, ciphertext, {
        onProgress: async (info) => {
          known[info.blockIndex * BLOCK_SIZE + info.bytePos] = String.fromCharCode(info.recoveredByte);
          renderRecovered(recoveredBox, known.join(""));
          statusSpan.textContent =
            `Recovering Block ${info.blockIndex + 1}/${info.totalBlocks} | Byte ${BLOCK_SIZE - info.bytePos}/${BLOCK_SIZE} | Oracle queries: ${info.queries}`;
          await sleep(15);
        },
      });

      recoveredBox.textContent = utf8Decode(result.unpaddedPlaintext);
      statusSpan.textContent = `Done in ${result.queryCount} total queries.`;

      setVerdict(verdictDiv, "bad",
        "⚠️ ", bold("Plaintext completely recovered without the key!"),
        ` Total oracle calls: ${result.queryCount} (avg ${(result.queryCount / ciphertext.length).toFixed(1)} queries/byte).`);
    } catch (error) {
      reportFailure(statusSpan, verdictDiv, error);
    } finally {
      btnRun.disabled = false;
    }
  });
}

// ===========================================================================
// DEMO 3: Vector 3 — BEAST Predictable IV Attack
// ===========================================================================
function initBeastDemo() {
  const btnRun = document.getElementById("beast-run");
  const cookieIn = document.getElementById("beast-cookie");
  const statusSpan = document.getElementById("beast-status");
  const recoveredBox = document.getElementById("beast-recovered");
  const verdictDiv = document.getElementById("beast-verdict");

  if (!btnRun) return;

  btnRun.addEventListener("click", async () => {
    btnRun.disabled = true;
    clearVerdict(verdictDiv);
    renderRecovered(recoveredBox, "");
    statusSpan.textContent = "Connecting to chained IV session...";

    try {
      const secretCookie = cookieIn.value || "SESSION=sec_99a8b7c6";
      const session = new ChainedIvSession(secretCookie);

      const recovered = await recoverSecretViaBeast(session, secretCookie.length, {
        onStep: async (s) => {
          renderRecovered(recoveredBox, s.recovered);
          statusSpan.textContent = `Recovering byte ${s.index + 1}/${secretCookie.length} ('${s.char}')...`;
          await sleep(30);
        },
      });

      recoveredBox.textContent = latin1Decode(recovered);
      statusSpan.textContent = `Session cookie recovered (${recovered.length}/${secretCookie.length} bytes).`;

      setVerdict(verdictDiv, "bad",
        "🚨 ", bold("IND-CPA Broken (BEAST Attack)!"),
        " By predicting the next IV on the TLS 1.0 connection, the secret was recovered byte-by-byte via chosen plaintext.");
    } catch (error) {
      reportFailure(statusSpan, verdictDiv, error);
    } finally {
      btnRun.disabled = false;
    }
  });
}

// ===========================================================================
// DEMO 4: Vector 4 — CBC-R Ciphertext Forgery
// ===========================================================================
function initForgeryDemo() {
  const btnRun = document.getElementById("frg-run");
  const payloadIn = document.getElementById("frg-payload");
  const statusSpan = document.getElementById("frg-status");
  const outDiv = document.getElementById("frg-out");
  const verdictDiv = document.getElementById("frg-verdict");

  if (!btnRun) return;

  btnRun.addEventListener("click", async () => {
    btnRun.disabled = true;
    clearVerdict(verdictDiv);
    replace(outDiv);
    statusSpan.textContent = "Starting backwards synthesis using padding oracle...";

    try {
      const serverKey = randomKey();
      const oracle = makePaddingOracle(serverKey);
      const chosenPayload = payloadIn.value || "user=admin;role=superadmin;access=all;status=authorized";

      const forged = await forgeCiphertextWithOracle(oracle, chosenPayload, {
        onBlockForged: async (info) => {
          statusSpan.textContent = `Synthesizing Block ${info.blockIndex + 1}/${info.totalBlocks} backwards...`;
          await sleep(25);
        },
      });

      statusSpan.textContent = "Ciphertext forged successfully.";

      // Verify what the server's real decryption produces:
      const decrypted = await aesCbcDecrypt(serverKey, forged.ciphertext, forged.iv, true);

      replace(outDiv,
        block({ className: "blk safe", label: "Forged IV (Calculated by CBC-R — the attacker must be able to supply it)", value: toHex(forged.iv) }),
        block({ className: "blk safe", label: `Forged Ciphertext (${forged.ciphertext.length} bytes)`, value: toHex(forged.ciphertext), spaced: true }),
        block({ label: "Server Decrypted Plaintext (Zero errors, valid PKCS#7)", value: latin1Decode(decrypted), valueClass: "tok", spaced: true }),
      );

      setVerdict(verdictDiv, "bad",
        "🚨 ", bold("Arbitrary Ciphertext Forgery (CBC-R)!"),
        " The attacker synthesized valid ciphertext for their chosen message using ONLY the decryption padding oracle — zero key access and zero encryption function calls. Every block lands as chosen because the forged IV is accepted; against an endpoint that fixes the IV, the first block would decrypt to garbage.");
    } catch (error) {
      reportFailure(statusSpan, verdictDiv, error);
    } finally {
      btnRun.disabled = false;
    }
  });
}

// ===========================================================================
// DEMO 5: Defensive Control — AES-GCM Tamper Rejection
// ===========================================================================
function initGcmDemo() {
  const btnRun = document.getElementById("gcm-run");
  const outDiv = document.getElementById("gcm-out");
  const verdictDiv = document.getElementById("gcm-verdict");

  if (!btnRun) return;

  btnRun.addEventListener("click", async () => {
    btnRun.disabled = true;
    try {
      const { tamperRejected, decryptedProfile } = await gcmTokenRoundtrip("alice");

      replace(outDiv,
        block({ className: "blk safe", label: "Authentic Plaintext", value: decryptedProfile, valueClass: "tok" }),
        block({
          className: "blk tampered",
          label: "Tamper Action",
          value: "Flipped bit 0 in ciphertext block. When decrypted by Web Crypto AES-GCM...",
          valueClass: "tok",
          spaced: true,
        }),
      );

      setVerdict(verdictDiv, "good",
        "🛡️ ", bold("Authentication Tag Verified: Tampering REJECTED!"),
        ` (${tamperRejected ? "OperationError: Mac check failed" : "Passed"}). Not a single byte of untrusted plaintext was emitted.`);
    } catch (error) {
      reportFailure(null, verdictDiv, error);
    } finally {
      btnRun.disabled = false;
    }
  });
}

// Initialize all demos when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
  initBitFlipDemo();
  initPaddingOracleDemo();
  initBeastDemo();
  initForgeryDemo();
  initGcmDemo();
});
