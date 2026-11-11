// Runs the real CLI against a local TLS server with the test certificate and a fake ACME server
// that only answers for that certificate's ID, as worked out by an independent parser.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { createServer as createTlsServer } from "node:tls";
import { fileURLToPath } from "node:url";

import "reflect-metadata"; // @peculiar/x509 needs it loaded first
import * as x509 from "@peculiar/x509";

const MAIN = fileURLToPath(new URL("../src/main.ts", import.meta.url));
const fixture = (name: string) => readFileSync(new URL(`fixtures/${name}`, import.meta.url), "utf8");

const certificate = new x509.X509Certificate(fixture("localhost.pem"));
const keyId = certificate.getExtension(x509.AuthorityKeyIdentifierExtension)?.keyId ?? "";
const ID = `${Buffer.from(keyId, "hex").toString("base64url")}.${Buffer.from("0087654321abcdef", "hex").toString("base64url")}`;

async function listen(server: import("node:net").Server): Promise<number> {
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  server.unref();
  return (server.address() as AddressInfo).port;
}

const tlsPort = await listen(createTlsServer({ cert: fixture("localhost.pem"), key: fixture("localhost.key") }, (s) => s.end()));
const expiredPort = await listen(createTlsServer({ cert: fixture("expired.pem"), key: fixture("localhost.key") }, (s) => s.end()));
const EXPIRED_ID = `${ID.split(".")[0]}.${Buffer.of(0x42).toString("base64url")}`;

let suggested = { start: "", end: "" };
let knowsCertificate = true;
const asked: string[] = [];
const acmePort = await listen(
  createHttpServer((request, response) => {
    asked.push(request.url ?? "");
    response.setHeader("content-type", "application/json");
    if (request.url === "/directory") response.end(JSON.stringify({ renewalInfo: `http://127.0.0.1:${acmePort}/renewal-info` }));
    else if (request.url === `/renewal-info/${ID}` && knowsCertificate) response.end(JSON.stringify({ suggestedWindow: suggested }));
    else response.writeHead(404).end("{}");
  }),
);

/** Runs the CLI without blocking: the servers above live in this process. */
function run(...args: string[]): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    execFile(process.execPath, [MAIN, ...args], (error, stdout, stderr) =>
      resolve({ code: error ? Number(error.code) : 0, out: stdout + stderr }),
    );
  });
}
const directory = (path = "directory") => ["--directory", `http://127.0.0.1:${acmePort}/${path}`];
const inDays = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

test("reports a window that hasn't opened yet and exits 0", async () => {
  suggested = { start: inDays(10), end: inDays(12) };
  const { code, out } = await run(...directory(), `127.0.0.1:${tlsPort}`);
  assert.equal(code, 0, out);
  assert.match(out, /localhost, issued by ari-check test CA Test Root \(not trusted here\)/);
  assert.match(out, /CA suggests renewing between .+: not yet/);
  assert.ok(asked.includes(`/renewal-info/${ID}`), "asked for the certificate's ID");
});

test("says to renew now once the window has opened, and exits 1", async () => {
  suggested = { start: inDays(-1), end: inDays(1) };
  const { code, out } = await run(...directory(), `127.0.0.1:${tlsPort}`, "--json");
  assert.equal(code, 1, out);
  const [result] = JSON.parse(out);
  assert.equal(result.plan.status, "due");
  assert.equal(result.plan.source, "ari");
  assert.equal(result.certId, ID);
});

test("falls back to two thirds of the lifetime when the CA doesn't know the certificate", async () => {
  knowsCertificate = false;
  try {
    const { code, out } = await run(...directory(), `127.0.0.1:${tlsPort}`);
    assert.equal(code, 0, out);
    assert.match(out, /the CA has no renewal information for this certificate; renew once two thirds .+: not yet/);
  } finally {
    knowsCertificate = true;
  }
});

test("reports an expired certificate without asking the CA about it, and exits 1", async () => {
  const { code, out } = await run(...directory(), `127.0.0.1:${expiredPort}`);
  assert.equal(code, 1, out);
  assert.match(out, /expired 2025-02-01 00:00 UTC\n {2}expired/);
  assert.ok(!asked.includes(`/renewal-info/${EXPIRED_ID}`), "RFC 9773 section 4.3: never ask about an expired certificate");
});

test("exits 2 for a missing directory, an unreachable host, or a bad target", async () => {
  const missing = await run(...directory("elsewhere"), `127.0.0.1:${tlsPort}`);
  assert.equal(missing.code, 2, missing.out);
  assert.match(missing.out, /HTTP 404/);
  const closed = await run(...directory(), "127.0.0.1:1");
  assert.equal(closed.code, 2, closed.out);
  assert.match(closed.out, /127\.0\.0\.1:1 {2}error:/);
  const bad = await run(...directory(), "host:notaport");
  assert.match(bad.out, /not a host or host:port/);
});

test("prints usage and exits 2 without hosts", async () => {
  const usage = await run();
  assert.equal(usage.code, 2);
  assert.match(usage.out, /usage: ari-check/);
});
