// Browser-level regression test for the deployed interaction paths.
// This complements the module tests by exercising the actual HTML, CSP, DOM wiring,
// Web Crypto implementation, progress callbacks, and success/failure banners.

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath, URL } from "node:url";
import { chromium } from "playwright";

const DOCS_ROOT = fileURLToPath(new URL("../docs/", import.meta.url));
const DOCS_ROOT_RESOLVED = path.resolve(DOCS_ROOT);
const CONTENT_TYPES = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".svg", "image/svg+xml"],
]);

function createStaticServer() {
  return http.createServer(async (request, response) => {
    try {
      const pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
      let target = path.resolve(DOCS_ROOT, `.${pathname}`);
      if (target !== DOCS_ROOT_RESOLVED && !target.startsWith(`${DOCS_ROOT_RESOLVED}${path.sep}`)) {
        response.writeHead(403).end("Forbidden");
        return;
      }
      if ((await stat(target)).isDirectory()) target = path.join(target, "index.html");
      const body = await readFile(target);
      response.writeHead(200, {
        "Content-Type": CONTENT_TYPES.get(path.extname(target)) ?? "application/octet-stream",
        "Cache-Control": "no-store",
      });
      response.end(body);
    } catch {
      response.writeHead(404).end("Not found");
    }
  });
}

test("browser UI completes every demonstration without external requests or runtime errors", async (t) => {
  const server = createStaticServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  assert.ok(address && typeof address === "object");
  const origin = `http://127.0.0.1:${address.port}`;

  const browser = await chromium.launch({ headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const runtimeErrors = [];
  const requests = [];
  page.on("console", (message) => {
    if (message.type() === "error") runtimeErrors.push(message.text());
  });
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  page.on("request", (request) => requests.push(request.url()));

  await page.goto(origin, { waitUntil: "networkidle" });
  assert.equal(await page.title(), "Why unauthenticated AES-CBC is unsafe — interactive");

  await page.getByRole("button", { name: "1. Issue Normal Token" }).click();
  await page.getByRole("button", { name: "2. Flip Bits to Escalate to Admin" }).click();
  assert.match(await page.locator("#bf-verdict").innerText(), /Access GRANTED as ADMIN/);

  await page.getByLabel("Secret text to encrypt and recover").fill("A");
  await page.getByRole("button", { name: "Run Padding Oracle Attack" }).click();
  await page.getByText(/Plaintext completely recovered without the key/).waitFor();
  assert.equal(await page.locator("#orc-recovered").innerText(), "A");

  await page.getByLabel("Target payload to forge").fill("A");
  await page.getByRole("button", { name: "Synthesize Forged Ciphertext" }).click();
  await page.getByText(/Arbitrary Ciphertext Forgery/).waitFor();
  assert.match(await page.locator("#frg-out").innerText(), /Server Decrypted Plaintext.*A/s);

  await page.getByLabel("Secret session cookie held by connection").fill("A");
  await page.getByRole("button", { name: "Execute BEAST Attack" }).click();
  await page.getByText(/IND-CPA Broken/).waitFor();
  assert.equal(await page.locator("#beast-recovered").innerText(), "A");

  await page.getByRole("button", { name: "Encrypt with GCM & Tamper Ciphertext" }).click();
  await page.getByText(/Authentication Tag Verified/).waitFor();
  assert.match(await page.locator("#gcm-verdict").innerText(), /Tampering REJECTED/);

  assert.deepEqual(runtimeErrors, []);
  assert.ok(requests.length > 1);
  assert.ok(requests.every((url) => url.startsWith(origin)), `unexpected external request: ${requests.join(", ")}`);
});
