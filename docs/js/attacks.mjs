// The four CBC attack vectors, implemented as testable modules shared by the
// interactive web documentation and the automated test suite.
//
// All crypto runs on standard Web Crypto AES (see crypto.mjs).
//
// Scope: Educational & defensive research. Every oracle and service runs in-process
// against self-contained mock interfaces — no third-party or production targets.

import {
  BLOCK_SIZE, aesCbcEncrypt, aesCbcDecrypt, aesGcmEncrypt, aesGcmDecrypt,
  randomKey, randomIv, randomBytes, concat, blockAt, splitBlocks, bytesEqual, xorBytes,
  padPkcs7, unpadPkcs7, isValidPkcs7, utf8, utf8Decode, latin1Encode, latin1Decode,
} from "./crypto.mjs";

// ===========================================================================
// VECTOR 1: CBC Bit-Flipping / Ciphertext Malleability
//
// In CBC mode: P_i = D_K(C_i) XOR C_{i-1} (where C_0 = IV).
// Flipping bit j in C_{i-1} produces an identical bit-flip in P_i upon decryption,
// while scrambling P_{i-1} into pseudorandom garbage.
// ===========================================================================

export class ProfileCookieService {
  constructor(key = randomKey()) {
    this.key = key;
  }

  // Issues an encrypted token with profile attributes:
  // "comment1=preview;userdata_input=<input>;comment2=standard_user;role=user"
  // Prefix "comment1=preview;userdata_input=" is exactly 32 bytes (2 blocks: 0 and 1).
  // Thus user-supplied data starts precisely at block 2 (offset 32).
  async issueToken(userData) {
    const sanitized = String(userData).replace(/[;=]/g, "");
    const profile = `comment1=preview;userdata_input=${sanitized};comment2=standard_user;role=user`;
    const iv = randomIv();
    const { ciphertext } = await aesCbcEncrypt(this.key, latin1Encode(profile), iv, true);
    return { iv, ciphertext };
  }

  // Decrypts token and checks whether it grants admin privileges
  async verifyToken(iv, ciphertext) {
    try {
      const rawPt = await aesCbcDecrypt(this.key, ciphertext, iv, true);
      const text = latin1Decode(rawPt);
      const hasAdmin = text.includes(";role=admin;") || text.endsWith(";role=admin") || text.includes(";admin=true;");
      return { valid: true, text, isAdmin: hasAdmin };
    } catch {
      return { valid: false, text: null, isAdmin: false };
    }
  }
}

// Bit-flipping attack function:
// Targets a specific substring in block i by flipping bits in block i-1 (or IV for block 0)
export function flipCbcBits(iv, ciphertext, targetBlockIndex, byteOffsetInBlock, delta) {
  const modIv = new Uint8Array(iv);
  const modCt = new Uint8Array(ciphertext);

  if (targetBlockIndex === 0) {
    modIv[byteOffsetInBlock] ^= delta;
  } else {
    const prevBlockStart = (targetBlockIndex - 1) * BLOCK_SIZE;
    modCt[prevBlockStart + byteOffsetInBlock] ^= delta;
  }
  return { iv: modIv, ciphertext: modCt };
}

// High-level automated forge for Vector 1:
export async function forgeAdminViaBitFlip(service) {
  // Prefix is 32 bytes (blocks 0 and 1).
  // Our payload starts at index 0 of block 2.
  // We supply ":role<admin"
  // ':' (0x3A) XOR ';' (0x3B) = 0x01 (offset 0 in block 2)
  // '<' (0x3C) XOR '=' (0x3D) = 0x01 (offset 5 in block 2)
  const placeholder = ":role<admin";
  const { iv, ciphertext } = await service.issueToken(placeholder);

  const deltaColonToSemi = ":".charCodeAt(0) ^ ";".charCodeAt(0);
  const deltaLessToEqual = "<".charCodeAt(0) ^ "=".charCodeAt(0);

  // Flip in block 1 to mutate block 2
  const flip1 = flipCbcBits(iv, ciphertext, 2, 0, deltaColonToSemi);
  const flip2 = flipCbcBits(flip1.iv, flip1.ciphertext, 2, 5, deltaLessToEqual);

  return flip2;
}

// ===========================================================================
// VECTOR 2: Padding Oracle Decryption (Vaudenay 2002)
//
// If a server reveals whether decrypted ciphertext has valid PKCS#7 padding
// (via error messages, HTTP status codes, or response timing), an attacker can
// recover the complete plaintext byte-by-byte in <= 256 queries per byte.
// ===========================================================================

export function makePaddingOracle(key = randomKey()) {
  let queryCount = 0;
  const oracle = async (iv, ciphertext) => {
    queryCount++;
    try {
      const pt = await aesCbcDecrypt(key, ciphertext, iv, false);
      return isValidPkcs7(pt);
    } catch {
      return false;
    }
  };
  oracle.getQueryCount = () => queryCount;
  oracle.resetQueryCount = () => { queryCount = 0; };
  return oracle;
}

// Recovers intermediate state I = D_K(targetBlock) for a single 16-byte block
export async function recoverIntermediateBlock(oracle, targetBlock, { onByteRecovered } = {}) {
  const intermediate = new Uint8Array(BLOCK_SIZE);
  const probe = new Uint8Array(BLOCK_SIZE);

  // Recover from byte 15 down to 0
  for (let bytePos = BLOCK_SIZE - 1; bytePos >= 0; bytePos--) {
    const padVal = BLOCK_SIZE - bytePos; // target padding byte (0x01, 0x02, ...)

    // Set previously recovered bytes in probe so they decrypt to padVal
    for (let j = bytePos + 1; j < BLOCK_SIZE; j++) {
      probe[j] = intermediate[j] ^ padVal;
    }

    let foundCandidate = null;
    for (let candidate = 0; candidate < 256; candidate++) {
      probe[bytePos] = candidate;
      const valid = await oracle(probe, targetBlock);
      if (valid) {
        // Guard against false positive when padVal == 1 (e.g. if plaintext naturally ends in 0x02 0x02)
        if (padVal === 1 && bytePos > 0) {
          probe[bytePos - 1] ^= 0x01; // mutate previous byte
          const verify = await oracle(probe, targetBlock);
          probe[bytePos - 1] ^= 0x01; // restore
          if (!verify) continue; // false positive, continue search
        }
        foundCandidate = candidate;
        break;
      }
    }

    if (foundCandidate === null) {
      throw new Error(`Padding oracle failed to find candidate for byte position ${bytePos}`);
    }

    const intermediateByte = foundCandidate ^ padVal;
    intermediate[bytePos] = intermediateByte;

    if (onByteRecovered) {
      await onByteRecovered({
        bytePos,
        padVal,
        candidate: foundCandidate,
        intermediateByte,
      });
    }
  }

  return intermediate;
}

// Decrypts multi-block ciphertext using the padding oracle
export async function recoverPlaintextWithOracle(oracle, iv, ciphertext, { onProgress } = {}) {
  const blocks = splitBlocks(ciphertext);
  const recoveredBlocks = [];
  let prevBlock = iv;

  for (let bIndex = 0; bIndex < blocks.length; bIndex++) {
    const currentBlock = blocks[bIndex];
    const intermediate = await recoverIntermediateBlock(oracle, currentBlock, {
      onByteRecovered: async (info) => {
        if (onProgress) {
          const ptByte = info.intermediateByte ^ prevBlock[info.bytePos];
          await onProgress({
            blockIndex: bIndex,
            totalBlocks: blocks.length,
            bytePos: info.bytePos,
            recoveredByte: ptByte,
            intermediate: new Uint8Array(intermediate),
            queries: oracle.getQueryCount(),
          });
        }
      },
    });

    const ptBlock = xorBytes(intermediate, prevBlock);
    recoveredBlocks.push(ptBlock);
    prevBlock = currentBlock;
  }

  const fullRawPt = concat(...recoveredBlocks);
  return {
    rawPlaintext: fullRawPt,
    unpaddedPlaintext: unpadPkcs7(fullRawPt),
    queryCount: oracle.getQueryCount(),
  };
}

// ===========================================================================
// VECTOR 3: Predictable IV / Chained-IV Chosen-Plaintext Attack (BEAST)
//
// In SSL 3.0 and TLS 1.0, the IV for record N+1 was the last ciphertext block
// of record N (chained IV). This allows a chosen-plaintext adversary to test
// guesses for secret bytes by aligning guesses with target ciphertext blocks.
// ===========================================================================

export class ChainedIvSession {
  constructor(secretCookie, key = randomKey()) {
    this.secretCookie = typeof secretCookie === "string" ? latin1Encode(secretCookie) : secretCookie;
    this.key = key;
    this.lastCiphertextBlock = randomIv(); // Initial connection IV
    this.history = [];
  }

  // Returns the predictable next IV
  getNextIv() {
    return new Uint8Array(this.lastCiphertextBlock);
  }

  // Encrypts (userPrefix || secretCookie) under the chained IV
  async sendRequest(userPrefix) {
    const iv = this.getNextIv();
    const prefixBytes = typeof userPrefix === "string" ? latin1Encode(userPrefix) : userPrefix;
    const message = concat(prefixBytes, this.secretCookie);
    const { ciphertext } = await aesCbcEncrypt(this.key, message, iv, true);
    this.lastCiphertextBlock = ciphertext.slice(ciphertext.length - BLOCK_SIZE);
    this.history.push({ iv, ciphertext, message });
    return { iv, ciphertext };
  }
}

// BEAST byte-by-byte chosen-plaintext recovery
export async function recoverSecretViaBeast(session, secretLength, { onStep } = {}) {
  const recovered = [];

  for (let i = 0; i < secretLength; i++) {
    // 1. Send prefix to align the unknown secret byte at the end of block 0
    // Pad length: 15 for byte 0, 14 for byte 1, etc.
    const padLen = (BLOCK_SIZE - 1 - (i % BLOCK_SIZE) + BLOCK_SIZE) % BLOCK_SIZE;
    const padding = new Uint8Array(padLen).fill("A".charCodeAt(0));

    // Target request: capture target ciphertext block C_target
    const { iv: targetIv, ciphertext: targetCt } = await session.sendRequest(padding);
    const targetBlockIndex = Math.floor((padLen + i) / BLOCK_SIZE);
    const targetBlock = blockAt(targetCt, targetBlockIndex);
    const prevBlockForTarget = targetBlockIndex === 0 ? targetIv : blockAt(targetCt, targetBlockIndex - 1);

    // 2. Test candidate bytes using predictable next IV
    let foundByte = null;
    for (let c = 32; c <= 126; c++) { // test printable ASCII
      const nextIv = session.getNextIv();

      // We want the cipher input for block 0 of our guess to match the target cipher input:
      // Target input was: prevBlockForTarget XOR (known_prefix || candidate)
      // Guess message will be XORed with nextIv upon encryption:
      // Guess cipher input = P_guess XOR nextIv.
      // Setting P_guess = nextIv XOR prevBlockForTarget XOR (known_prefix || candidate)
      // makes Guess cipher input = prevBlockForTarget XOR (known_prefix || candidate)!
      const knownContext = concat(
        padding,
        Uint8Array.from(recovered.slice(Math.max(0, recovered.length - (BLOCK_SIZE - 1 - padLen)))),
        Uint8Array.of(c)
      );

      const guessPlaintextBlock = xorBytes(xorBytes(nextIv, prevBlockForTarget), knownContext);
      const { ciphertext: probeCt } = await session.sendRequest(guessPlaintextBlock);
      const probeBlock0 = blockAt(probeCt, 0);

      if (bytesEqual(probeBlock0, targetBlock)) {
        foundByte = c;
        break;
      }
    }

    if (foundByte === null) {
      // Fallback full byte search (0..255)
      for (let c = 0; c < 256; c++) {
        if (c >= 32 && c <= 126) continue;
        const nextIv = session.getNextIv();
        const knownContext = concat(
          padding,
          Uint8Array.from(recovered.slice(Math.max(0, recovered.length - (BLOCK_SIZE - 1 - padLen)))),
          Uint8Array.of(c)
        );
        const guessPlaintextBlock = xorBytes(xorBytes(nextIv, prevBlockForTarget), knownContext);
        const { ciphertext: probeCt } = await session.sendRequest(guessPlaintextBlock);
        if (bytesEqual(blockAt(probeCt, 0), targetBlock)) {
          foundByte = c;
          break;
        }
      }
    }

    if (foundByte === null) break;
    recovered.push(foundByte);

    if (onStep) {
      await onStep({
        index: i,
        byte: foundByte,
        char: String.fromCharCode(foundByte),
        recovered: latin1Decode(Uint8Array.from(recovered)),
      });
    }
  }

  return Uint8Array.from(recovered);
}

// ===========================================================================
// VECTOR 4: CBC Padding Oracle Ciphertext Forgery (CBC-R)
//
// An attacker with ONLY access to a decryption padding oracle (no key, no
// encryption oracle) can forge valid ciphertext for ANY chosen plaintext!
// Working backwards from the last block:
// C_{i-1} = D_K(C_i) XOR P_i = I_i XOR P_i
// ===========================================================================

export async function forgeCiphertextWithOracle(oracle, chosenPlaintext, { onBlockForged } = {}) {
  const ptBytes = typeof chosenPlaintext === "string" ? latin1Encode(chosenPlaintext) : chosenPlaintext;
  const paddedPt = padPkcs7(ptBytes);
  const ptBlocks = splitBlocks(paddedPt);
  const forgedCipherBlocks = new Array(ptBlocks.length);

  // 1. Pick a random trailing ciphertext block C_n
  let currentCtBlock = randomBytes(BLOCK_SIZE);
  forgedCipherBlocks[ptBlocks.length - 1] = currentCtBlock;

  // 2. Work backwards from block n down to block 1
  for (let i = ptBlocks.length - 1; i >= 0; i--) {
    const targetPt = ptBlocks[i];
    // Recover intermediate state I_i = D_K(currentCtBlock)
    const intermediate = await recoverIntermediateBlock(oracle, currentCtBlock);

    // Compute previous ciphertext block (or IV if i == 0):
    // C_{i-1} = I_i XOR P_i
    const prevCtBlock = xorBytes(intermediate, targetPt);

    if (i > 0) {
      forgedCipherBlocks[i - 1] = prevCtBlock;
      currentCtBlock = prevCtBlock;
    } else {
      // i == 0: prevCtBlock is the IV
      const forgedIv = prevCtBlock;
      const fullCiphertext = concat(...forgedCipherBlocks);

      if (onBlockForged) {
        await onBlockForged({
          blockIndex: i,
          totalBlocks: ptBlocks.length,
          intermediate,
          forgedBlock: prevCtBlock,
        });
      }

      return { iv: forgedIv, ciphertext: fullCiphertext };
    }

    if (onBlockForged) {
      await onBlockForged({
        blockIndex: i,
        totalBlocks: ptBlocks.length,
        intermediate,
        forgedBlock: prevCtBlock,
      });
    }
  }
}

// ===========================================================================
// DEFENSIVE CONTROL: Authenticated Encryption (AES-GCM)
// ===========================================================================

export async function gcmTokenRoundtrip(userData, key = randomKey()) {
  const profile = `comment1=preview;userdata=${userData};role=user`;
  const iv = randomIv(12);
  const { ciphertext } = await aesGcmEncrypt(key, utf8(profile), iv);

  // Tamper with a single byte in ciphertext
  const tamperedCt = new Uint8Array(ciphertext);
  tamperedCt[0] ^= 0x01;

  let tamperRejected = false;
  try {
    await aesGcmDecrypt(key, tamperedCt, iv);
  } catch {
    tamperRejected = true; // GCM auth tag rejected modified ciphertext
  }

  const validPt = await aesGcmDecrypt(key, ciphertext, iv);
  return {
    tamperRejected,
    decryptedProfile: utf8Decode(validPt),
  };
}
