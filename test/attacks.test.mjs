// Automated test suite for AES-CBC weaknesses and Web Crypto operations.
// Verified against official NIST SP 800-38A Section F.2.1 test vectors.
// Run with: `node --test`.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  aesCbcEncrypt, aesCbcDecrypt,
  padPkcs7, unpadPkcs7, isValidPkcs7, fromHex, toHex, utf8, utf8Decode,
  randomKey, randomIv,
} from "../docs/js/crypto.mjs";

import {
  ProfileCookieService, forgeAdminViaBitFlip,
  makePaddingOracle, recoverPlaintextWithOracle,
  ChainedIvSession, recoverSecretViaBeast,
  forgeCiphertextWithOracle, gcmTokenRoundtrip,
} from "../docs/js/attacks.mjs";

test("AES-128-CBC matches official NIST SP 800-38A Section F.2.1 test vectors", async () => {
  const key = fromHex("2b7e151628aed2a6abf7158809cf4f3c");
  const iv = fromHex("000102030405060708090a0b0c0d0e0f");
  const pt = fromHex(
    "6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51" +
    "30c81c46a35ce411e5fbc1191a0a52ef" + "f69f2445df4f9b17ad2b417be66c3710"
  );
  const want =
    "7649abac8119b246cee98e9b12e9197d" + "5086cb9b507219ee95db113a917678b2" +
    "73bed6b8e3c1743b7116e69e22229516" + "3ff1caa1681fac09120eca307586e1a7";

  const { ciphertext } = await aesCbcEncrypt(key, pt, iv, /* pad */ false);
  assert.equal(toHex(ciphertext), want);

  const decrypted = await aesCbcDecrypt(key, ciphertext, iv, /* unpad */ false);
  assert.equal(toHex(decrypted), toHex(pt));
});

test("PKCS#7 padding and unpadding validates correctly", () => {
  const data15 = utf8("123456789012345"); // 15 bytes -> 1 byte pad (0x01)
  const padded15 = padPkcs7(data15);
  assert.equal(padded15.length, 16);
  assert.equal(padded15[15], 1);
  assert.equal(isValidPkcs7(padded15), true);
  assert.deepEqual(unpadPkcs7(padded15), data15);

  const data16 = utf8("1234567890123456"); // 16 bytes -> 16 byte pad (0x10)
  const padded16 = padPkcs7(data16);
  assert.equal(padded16.length, 32);
  assert.equal(padded16[31], 16);
  assert.equal(isValidPkcs7(padded16), true);
  assert.deepEqual(unpadPkcs7(padded16), data16);

  // Corrupted padding
  const badPad = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 5]);
  assert.equal(isValidPkcs7(badPad), false);
  assert.throws(() => unpadPkcs7(badPad));
});

test("Vector 1 — Bit-flipping escalates user privilege without knowing the key", async () => {
  const service = new ProfileCookieService();
  const normal = await service.issueToken("regular_user");
  const normalCheck = await service.verifyToken(normal.iv, normal.ciphertext);
  assert.equal(normalCheck.valid, true);
  assert.equal(normalCheck.isAdmin, false);

  const forged = await forgeAdminViaBitFlip(service);
  const adminCheck = await service.verifyToken(forged.iv, forged.ciphertext);
  assert.equal(adminCheck.valid, true);
  assert.equal(adminCheck.isAdmin, true);
});

test("Vector 2 — Padding oracle recovers multi-block secret ciphertext", async () => {
  const key = randomKey();
  const iv = randomIv();
  const secretText = "Confidential Banking Payload: Transfer $50,000 to Account #987654";
  const { ciphertext } = await aesCbcEncrypt(key, utf8(secretText), iv, true);

  const oracle = makePaddingOracle(key);
  const result = await recoverPlaintextWithOracle(oracle, iv, ciphertext);

  assert.equal(utf8Decode(result.unpaddedPlaintext), secretText);
  assert.ok(result.queryCount > 0);
  assert.ok(result.queryCount <= 256 * ciphertext.length);
});

test("Vector 3 — Predictable/chained IV breaks IND-CPA and recovers secret (BEAST)", async () => {
  const secretCookie = "FLAG{BEAST_IV}";
  const session = new ChainedIvSession(secretCookie);

  const recovered = await recoverSecretViaBeast(session, secretCookie.length);
  assert.equal(utf8Decode(recovered), secretCookie);
});

test("Vector 4 — CBC-R forges valid ciphertext for arbitrary chosen plaintext", async () => {
  const key = randomKey();
  const oracle = makePaddingOracle(key);

  const chosenPlaintext = "authorized_role=superadmin;account_id=0001;status=active";
  const { iv, ciphertext } = await forgeCiphertextWithOracle(oracle, chosenPlaintext);

  // Decrypt with real key to verify that the server accepts the forged ciphertext
  const decrypted = await aesCbcDecrypt(key, ciphertext, iv, true);
  assert.equal(utf8Decode(decrypted), chosenPlaintext);
});

test("Defensive — AES-GCM rejects tampered ciphertext before any data is trusted", async () => {
  const { tamperRejected, decryptedProfile } = await gcmTokenRoundtrip("alice");
  assert.equal(tamperRejected, true);
  assert.match(decryptedProfile, /userdata=alice/);
});
