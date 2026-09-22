// AES primitives and helper functions for the CBC mode weakness demonstrations.
//
// All cryptographic operations execute via the standard Web Crypto API
// (globalThis.crypto.subtle), running identically in modern browsers and in Node 20+.
//
// CBC mode is implemented here with explicit IVs and PKCS#7 padding to demonstrate
// why unauthenticated CBC is vulnerable to bit-flipping, padding oracles, predictable IVs,
// and ciphertext forgery. AES-GCM is included as the primary authenticated fix.

const subtle = globalThis.crypto.subtle;
export const BLOCK_SIZE = 16;

function assertBytes(value, label) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${label} must be a Uint8Array`);
  }
}

function assertBlockSize(blockSize) {
  if (!Number.isInteger(blockSize) || blockSize < 1 || blockSize > 255) {
    throw new RangeError("block size must be an integer from 1 to 255");
  }
}

function assertAesKey(keyBytes) {
  assertBytes(keyBytes, "AES key");
  if (![16, 24, 32].includes(keyBytes.length)) {
    throw new RangeError("AES key must contain 16, 24, or 32 bytes");
  }
}

// ---- byte / string helpers ----
export const toHex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
export function fromHex(value) {
  const s = String(value);
  if (s.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(s)) {
    throw new RangeError("hex input must contain an even number of hexadecimal characters");
  }
  return new Uint8Array(s.match(/../g)?.map((h) => Number.parseInt(h, 16)) ?? []);
}
export const utf8 = (s) => new TextEncoder().encode(s);
export const utf8Decode = (b) => new TextDecoder().decode(b);
// latin1: one character <-> one byte (useful for raw byte-preserving strings).
// Reject characters outside the byte range instead of truncating them and later
// reporting a successful recovery of different data.
export function latin1Encode(value) {
  const chars = [...String(value)];
  const out = new Uint8Array(chars.length);
  chars.forEach((char, index) => {
    const codePoint = char.codePointAt(0);
    if (codePoint > 0xff) {
      throw new RangeError(`Character ${JSON.stringify(char)} cannot be represented as one Latin-1 byte`);
    }
    out[index] = codePoint;
  });
  return out;
}
export const latin1Decode = (b) => String.fromCharCode(...new Uint8Array(b));

export function concat(...arrays) {
  arrays.forEach((array, index) => assertBytes(array, `array ${index}`));
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrays) { out.set(a, o); o += a.length; }
  return out;
}

export function splitBlocks(data, blockSize = BLOCK_SIZE) {
  assertBytes(data, "data");
  assertBlockSize(blockSize);
  if (data.length % blockSize !== 0) {
    throw new RangeError("data length must be a multiple of block size");
  }
  const out = [];
  for (let i = 0; i < data.length; i += blockSize) out.push(data.slice(i, i + blockSize));
  return out;
}

export function blockAt(data, index, blockSize = BLOCK_SIZE) {
  assertBytes(data, "data");
  assertBlockSize(blockSize);
  if (!Number.isInteger(index) || index < 0) {
    throw new RangeError("block index must be a non-negative integer");
  }
  const start = index * blockSize;
  const end = start + blockSize;
  if (end > data.length) throw new RangeError(`block ${index} is outside the supplied data`);
  return data.slice(start, end);
}

export function bytesEqual(a, b) {
  assertBytes(a, "first value");
  assertBytes(b, "second value");
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function xorBytes(a, b) {
  assertBytes(a, "first XOR value");
  assertBytes(b, "second XOR value");
  if (a.length !== b.length) throw new RangeError("XOR inputs must have equal length");
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

export function randomBytes(len) {
  if (!Number.isInteger(len) || len < 1 || len > 65536) {
    throw new RangeError("random byte length must be an integer from 1 to 65536");
  }
  const b = new Uint8Array(len);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export function randomKey(len = BLOCK_SIZE) {
  return randomBytes(len);
}

export function randomIv(len = BLOCK_SIZE) {
  return randomBytes(len);
}

// ---- PKCS#7 padding ----
export function padPkcs7(data, blockSize = BLOCK_SIZE) {
  assertBytes(data, "data");
  assertBlockSize(blockSize);
  const padLen = blockSize - (data.length % blockSize);
  return concat(data, new Uint8Array(padLen).fill(padLen));
}

export function unpadPkcs7(data, blockSize = BLOCK_SIZE) {
  assertBytes(data, "data");
  assertBlockSize(blockSize);
  if (data.length === 0 || data.length % blockSize !== 0) {
    throw new Error("data length is not a multiple of block size");
  }
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > blockSize) {
    throw new Error("invalid PKCS#7 padding length");
  }
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error("invalid PKCS#7 padding byte");
  }
  return data.slice(0, data.length - padLen);
}

export function isValidPkcs7(data, blockSize = BLOCK_SIZE) {
  if (!(data instanceof Uint8Array)) return false;
  if (!Number.isInteger(blockSize) || blockSize < 1 || blockSize > 255) return false;
  if (data.length === 0 || data.length % blockSize !== 0) return false;
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > blockSize) return false;
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) return false;
  }
  return true;
}

// ---- Key handle cache ----
// Web Crypto key handles are immutable and safe to reuse. The demos import the same key
// thousands of times over (BEAST alone drives well over a thousand encryptions), and
// re-importing on every call dominates the wall-clock cost in the browser, so handles are
// memoized per (algorithm, usages, key bytes). Keys here are ephemeral, in-page demo keys.
const keyHandles = new Map();
const KEY_HANDLE_LIMIT = 32;

function importKeyCached(keyBytes, algorithm, usages) {
  const cacheKey = `${algorithm}|${usages.join(",")}|${toHex(keyBytes)}`;
  let handle = keyHandles.get(cacheKey);
  if (!handle) {
    handle = subtle.importKey("raw", keyBytes, { name: algorithm }, false, usages);
    if (keyHandles.size >= KEY_HANDLE_LIMIT) keyHandles.delete(keyHandles.keys().next().value);
    keyHandles.set(cacheKey, handle);
  }
  return handle;
}

// ---- Raw AES single-block primitive (via zero-IV CBC) ----
async function rawAesEncryptBlockK(cryptoKey, block16) {
  assertBytes(block16, "AES block");
  if (block16.length !== BLOCK_SIZE) throw new RangeError("AES block must contain 16 bytes");
  const zeroIv = new Uint8Array(BLOCK_SIZE);
  const ct = await subtle.encrypt({ name: "AES-CBC", iv: zeroIv }, cryptoKey, block16);
  return new Uint8Array(ct).slice(0, BLOCK_SIZE);
}

// ---- AES-CBC Encryption ----
export async function aesCbcEncrypt(keyBytes, plaintext, iv = randomIv(), pad = true) {
  assertAesKey(keyBytes);
  assertBytes(plaintext, "plaintext");
  assertBytes(iv, "CBC IV");
  if (iv.length !== BLOCK_SIZE) throw new RangeError("CBC IV must contain 16 bytes");
  const k = await importKeyCached(keyBytes, "AES-CBC", ["encrypt"]);
  if (pad) {
    const ct = await subtle.encrypt({ name: "AES-CBC", iv }, k, plaintext);
    return { iv: new Uint8Array(iv), ciphertext: new Uint8Array(ct) };
  } else {
    // Unpadded CBC: length must be multiple of 16. WebCrypto CBC appends 1 block of padding,
    // so we slice off the extra padding block.
    if (plaintext.length === 0 || plaintext.length % BLOCK_SIZE !== 0) {
      throw new Error("unpadded CBC requires non-empty, block-aligned input");
    }
    const ct = await subtle.encrypt({ name: "AES-CBC", iv }, k, plaintext);
    return { iv: new Uint8Array(iv), ciphertext: new Uint8Array(ct).slice(0, plaintext.length) };
  }
}

// ---- AES-CBC Decryption ----
export async function aesCbcDecrypt(keyBytes, ciphertext, iv, unpad = true) {
  assertAesKey(keyBytes);
  assertBytes(ciphertext, "ciphertext");
  assertBytes(iv, "CBC IV");
  if (iv.length !== BLOCK_SIZE) throw new RangeError("CBC IV must contain 16 bytes");
  if (ciphertext.length === 0 || ciphertext.length % BLOCK_SIZE !== 0) {
    throw new RangeError("CBC ciphertext must be a non-empty multiple of 16 bytes");
  }
  const k = await importKeyCached(keyBytes, "AES-CBC", ["decrypt", "encrypt"]);
  if (unpad) {
    const pt = await subtle.decrypt({ name: "AES-CBC", iv }, k, ciphertext);
    return new Uint8Array(pt);
  } else {
    // Raw unpadded decryption of N blocks:
    // WebCrypto strips PKCS#7 from the final block and throws if invalid.
    // To decrypt raw without error, we append a synthetic padding block X = E_K(C_last XOR 0x10^16).
    // Decrypting [ciphertext, X] with IV gives original plaintext for ciphertext, and
    // D_K(X) XOR C_last = 0x10^16 as the trailing block, which WebCrypto strips cleanly.
    if (ciphertext.length % BLOCK_SIZE !== 0 || ciphertext.length === 0) {
      throw new Error("ciphertext length must be non-zero multiple of block size");
    }
    const lastBlock = ciphertext.slice(ciphertext.length - BLOCK_SIZE);
    const xored = lastBlock.map((b) => b ^ BLOCK_SIZE);
    const X = await rawAesEncryptBlockK(k, xored);
    const pt = await subtle.decrypt({ name: "AES-CBC", iv }, k, concat(ciphertext, X));
    return new Uint8Array(pt);
  }
}

// ---- AES-GCM (Defensive fix: Authenticated Encryption with Associated Data) ----
export async function aesGcmEncrypt(keyBytes, plaintext, iv = randomIv(12), additionalData = new Uint8Array(0)) {
  assertAesKey(keyBytes);
  assertBytes(plaintext, "plaintext");
  assertBytes(iv, "GCM IV");
  assertBytes(additionalData, "additional data");
  if (iv.length !== 12) throw new RangeError("GCM IV must contain 12 bytes");
  const k = await importKeyCached(keyBytes, "AES-GCM", ["encrypt"]);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData, tagLength: 128 }, k, plaintext);
  return { iv: new Uint8Array(iv), ciphertext: new Uint8Array(ct) };
}

export async function aesGcmDecrypt(keyBytes, ciphertext, iv, additionalData = new Uint8Array(0)) {
  assertAesKey(keyBytes);
  assertBytes(ciphertext, "ciphertext");
  assertBytes(iv, "GCM IV");
  assertBytes(additionalData, "additional data");
  if (iv.length !== 12) throw new RangeError("GCM IV must contain 12 bytes");
  if (ciphertext.length < 16) throw new RangeError("GCM ciphertext must include a 16-byte tag");
  const k = await importKeyCached(keyBytes, "AES-GCM", ["decrypt"]);
  const pt = await subtle.decrypt({ name: "AES-GCM", iv, additionalData, tagLength: 128 }, k, ciphertext);
  return new Uint8Array(pt);
}
