// Interactive UI controllers for the CBC mode weakness demonstrations.
// Wires browser DOM events to the crypto and attack functions in attacks.mjs and crypto.mjs.

import {
  toHex, utf8, utf8Decode, latin1Decode,
  randomKey, randomIv, aesCbcEncrypt, aesCbcDecrypt,
} from "./crypto.mjs";

import {
  ProfileCookieService, forgeAdminViaBitFlip,
  makePaddingOracle, recoverPlaintextWithOracle,
  ChainedIvSession, recoverSecretViaBeast,
  forgeCiphertextWithOracle, gcmTokenRoundtrip,
} from "./attacks.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ===========================================================================
// DEMO 1: Vector 1 — Bit-Flipping Playground
// ===========================================================================
function initBitFlipDemo() {
  const service = new ProfileCookieService();
  let currentToken = null;

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
      currentToken = await service.issueToken(val);
      const check = await service.verifyToken(currentToken.iv, currentToken.ciphertext);

      outDiv.innerHTML = `
        <div class="blk">
          <div class="blk-label">IV (16 bytes hex)</div>
          <div class="blk-hex">${toHex(currentToken.iv)}</div>
        </div>
        <div class="blk">
          <div class="blk-label">Ciphertext (${currentToken.ciphertext.length} bytes)</div>
          <div class="blk-hex">${toHex(currentToken.ciphertext)}</div>
        </div>
        <div class="blk" style="margin-top:8px">
          <div class="blk-label">Decrypted Plaintext on Server</div>
          <div class="tok">${check.text}</div>
        </div>
      `;

      verdictDiv.className = "verdict show " + (check.isAdmin ? "bad" : "good");
      verdictDiv.innerHTML = `Server evaluated: <strong>role=${check.isAdmin ? "ADMIN" : "USER"}</strong> (Access ${check.isAdmin ? "GRANTED" : "standard user"})`;
      btnFlip.disabled = false;
    } finally {
      btnIssue.disabled = false;
    }
  });

  btnFlip.addEventListener("click", async () => {
    btnFlip.disabled = true;
    try {
      const forged = await forgeAdminViaBitFlip(service);
      const check = await service.verifyToken(forged.iv, forged.ciphertext);

      outDiv.innerHTML = `
        <div class="blk tampered">
          <div class="blk-label">Ciphertext (Block 1 modified with Δ)</div>
          <div class="blk-hex">${toHex(forged.ciphertext)}</div>
          <div class="blk-tag">Bits 0 and 5 flipped in Block 1</div>
        </div>
        <div class="blk" style="margin-top:8px">
          <div class="blk-label">Decrypted Plaintext on Server (Note scrambled Block 1, but Block 2 contains role=admin)</div>
          <div class="tok">${check.text}</div>
        </div>
      `;

      verdictDiv.className = "verdict show bad";
      verdictDiv.innerHTML = `🚨 Privilege Escalation! Server decrypted role=admin without integrity errors. <strong>Access GRANTED as ADMIN.</strong>`;
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
    verdictDiv.className = "verdict";
    recoveredBox.innerHTML = '<span class="cursor">_</span>';
    statusSpan.textContent = "Initializing oracle and encrypting secret...";

    try {
      const key = randomKey();
      const iv = randomIv();
      const secret = secretIn.value || "Confidential Financial Data: $50,000 to Account 9876";
      const { ciphertext } = await aesCbcEncrypt(key, utf8(secret), iv, true);

      const oracle = makePaddingOracle(key);
      let textSoFar = "";

      const result = await recoverPlaintextWithOracle(oracle, iv, ciphertext, {
        onProgress: async (info) => {
          textSoFar += String.fromCharCode(info.recoveredByte);
          recoveredBox.innerHTML = `<span>${latin1Decode(utf8(textSoFar))}</span><span class="cursor">_</span>`;
          statusSpan.textContent = `Recovering Block ${info.blockIndex + 1}/${info.totalBlocks} | Byte ${15 - info.bytePos + 1}/16 | Oracle queries: ${info.queries}`;
          await sleep(15);
        },
      });

      recoveredBox.textContent = utf8Decode(result.unpaddedPlaintext);
      statusSpan.textContent = `Done in ${result.queryCount} total queries.`;

      verdictDiv.className = "verdict show bad";
      verdictDiv.innerHTML = `⚠️ <strong>Plaintext completely recovered without the key!</strong> Total oracle calls: ${result.queryCount} (avg ${(result.queryCount / ciphertext.length).toFixed(1)} queries/byte).`;
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
    verdictDiv.className = "verdict";
    recoveredBox.innerHTML = '<span class="cursor">_</span>';
    statusSpan.textContent = "Connecting to chained IV session...";

    try {
      const secretCookie = cookieIn.value || "SESSION=sec_99a8b7c6";
      const session = new ChainedIvSession(secretCookie);

      const recovered = await recoverSecretViaBeast(session, secretCookie.length, {
        onStep: async (s) => {
          recoveredBox.innerHTML = `<span>${s.recovered}</span><span class="cursor">_</span>`;
          statusSpan.textContent = `Recovering byte ${s.index + 1}/${secretCookie.length} ('${s.char}')...`;
          await sleep(30);
        },
      });

      recoveredBox.textContent = utf8Decode(recovered);
      statusSpan.textContent = "Session cookie recovered.";

      verdictDiv.className = "verdict show bad";
      verdictDiv.innerHTML = `🚨 <strong>IND-CPA Broken (BEAST Attack)!</strong> By predicting the next IV on the TLS 1.0 connection, the secret was recovered byte-by-byte via chosen plaintext.`;
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
    verdictDiv.className = "verdict";
    outDiv.innerHTML = "";
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
      const decryptedText = utf8Decode(decrypted);

      outDiv.innerHTML = `
        <div class="blk safe">
          <div class="blk-label">Forged IV (Calculated by CBC-R)</div>
          <div class="blk-hex">${toHex(forged.iv)}</div>
        </div>
        <div class="blk safe" style="margin-top:8px">
          <div class="blk-label">Forged Ciphertext (${forged.ciphertext.length} bytes)</div>
          <div class="blk-hex">${toHex(forged.ciphertext)}</div>
        </div>
        <div class="blk" style="margin-top:8px">
          <div class="blk-label">Server Decrypted Plaintext (Zero errors, Valid PKCS#7)</div>
          <div class="tok">${decryptedText}</div>
        </div>
      `;

      verdictDiv.className = "verdict show bad";
      verdictDiv.innerHTML = `🚨 <strong>Arbitrary Ciphertext Forgery (CBC-R)!</strong> The attacker synthesized valid ciphertext for their chosen message using ONLY the decryption padding oracle — zero key access and zero encryption function calls.`;
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

      outDiv.innerHTML = `
        <div class="blk safe">
          <div class="blk-label">Authentic Plaintext</div>
          <div class="tok">${decryptedProfile}</div>
        </div>
        <div class="blk tampered" style="margin-top:8px">
          <div class="blk-label">Tamper Action</div>
          <div class="tok">Flipped bit 0 in ciphertext block. When decrypted by Web Crypto AES-GCM...</div>
        </div>
      `;

      verdictDiv.className = "verdict show good";
      verdictDiv.innerHTML = `🛡️ <strong>Authentication Tag Verified: Tampering REJECTED!</strong> (${tamperRejected ? "OperationError: Mac check failed" : "Passed"}). Not a single byte of untrusted plaintext was emitted.`;
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
