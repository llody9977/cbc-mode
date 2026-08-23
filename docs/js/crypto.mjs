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

// ---- byte / string helpers ----
export const toHex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
export const fromHex = (s) => new Uint8Array(s.match(/../g)?.map((h) => parseInt(h, 16)) ?? []);
export const utf8 = (s) => new TextEncoder().encode(s);
export const utf8Decode = (b) => new TextDecoder().decode(b);
// latin1: one char <-> one byte (useful for raw byte preserving strings)
export const latin1Encode = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff);
export const latin1Decode = (b) => String.fromCharCode(...new Uint8Array(b));

export function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrays) { out.set(a, o); o += a.length; }
  return out;
}

export function splitBlocks(data, blockSize = BLOCK_SIZE) {
  const out = [];
  for (let i = 0; i < data.length; i += blockSize) out.push(data.slice(i, i + blockSize));
  return out;
}

export function blockAt(data, index, blockSize = BLOCK_SIZE) {
  return data.slice(index * blockSize, (index + 1) * blockSize);
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function xorBytes(a, b) {
  const len = Math.min(a.length, b.length);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i];
  return out;
}

export function randomBytes(len) {
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
  const padLen = blockSize - (data.length % blockSize);
  return concat(data, new Uint8Array(padLen).fill(padLen));
}

export function unpadPkcs7(data, blockSize = BLOCK_SIZE) {
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
  const zeroIv = new Uint8Array(BLOCK_SIZE);
  const ct = await subtle.encrypt({ name: "AES-CBC", iv: zeroIv }, cryptoKey, block16);
  return new Uint8Array(ct).slice(0, BLOCK_SIZE);
}

// ---- AES-CBC Encryption ----
export async function aesCbcEncrypt(keyBytes, plaintext, iv = randomIv(), pad = true) {
  const k = await importKeyCached(keyBytes, "AES-CBC", ["encrypt"]);
  if (pad) {
    const ct = await subtle.encrypt({ name: "AES-CBC", iv }, k, plaintext);
    return { iv: new Uint8Array(iv), ciphertext: new Uint8Array(ct) };
  } else {
    // Unpadded CBC: length must be multiple of 16. WebCrypto CBC appends 1 block of padding,
    // so we slice off the extra padding block.
    if (plaintext.length % BLOCK_SIZE !== 0) throw new Error("unpadded CBC requires block-aligned input");
    const ct = await subtle.encrypt({ name: "AES-CBC", iv }, k, plaintext);
    return { iv: new Uint8Array(iv), ciphertext: new Uint8Array(ct).slice(0, plaintext.length) };
  }
}

// ---- AES-CBC Decryption ----
export async function aesCbcDecrypt(keyBytes, ciphertext, iv, unpad = true) {
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
  const k = await importKeyCached(keyBytes, "AES-GCM", ["encrypt"]);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData, tagLength: 128 }, k, plaintext);
  return { iv: new Uint8Array(iv), ciphertext: new Uint8Array(ct) };
}

export async function aesGcmDecrypt(keyBytes, ciphertext, iv, additionalData = new Uint8Array(0)) {
  const k = await importKeyCached(keyBytes, "AES-GCM", ["decrypt"]);
  const pt = await subtle.decrypt({ name: "AES-GCM", iv, additionalData, tagLength: 128 }, k, ciphertext);
  return new Uint8Array(pt);
}
