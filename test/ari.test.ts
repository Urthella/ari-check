import assert from "node:assert/strict";
import { test } from "node:test";

import { type RenewalInfo, directoryFor, plan, renewalInfo, retryAfter } from "../src/ari.ts";

const NOW = new Date("2026-11-11T12:00:00Z");
const DIRECTORY = "https://ca.example/directory";

/** A fake CA: the directory, and renewal info at whatever the test supplies. */
function fakeCa(renewal: () => Response, directory: object = { renewalInfo: "https://ca.example/renewal-info/" }) {
  const urls: string[] = [];
  const fetch = async (url: string) => {
    urls.push(url);
    return url === DIRECTORY ? Response.json(directory) : renewal();
  };
  return { fetch, urls };
}

const window = (start: string, end: string, extra: object = {}) => ({ suggestedWindow: { start, end }, ...extra });

test("asks the renewalInfo URL from the directory, under the certificate's ID", async () => {
  const ca = fakeCa(() =>
    Response.json(window("2026-12-01T00:00:00Z", "2026-12-03T00:00:00Z", { explanationURL: "https://ca.example/why" }), {
      headers: { "retry-after": "21600" },
    }),
  );
  const info = await renewalInfo(DIRECTORY, "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE", NOW, ca.fetch);
  assert.deepEqual(ca.urls, [DIRECTORY, "https://ca.example/renewal-info/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"]);
  assert.deepEqual(info, {
    kind: "window",
    start: new Date("2026-12-01T00:00:00Z"),
    end: new Date("2026-12-03T00:00:00Z"),
    explanationURL: "https://ca.example/why",
    retryAfterSeconds: 21600,
  });
});

test("tells apart a CA without ARI, an unknown certificate, and replies the RFC says to ignore", async () => {
  const kind = async (renewal: () => Response, directory?: object) =>
    (await renewalInfo(DIRECTORY, "id", NOW, fakeCa(renewal, directory).fetch)).kind;
  assert.equal(await kind(() => Response.json({}), { newOrder: "x" }), "unsupported");
  assert.equal(await kind(() => new Response("", { status: 404 })), "unknown");
  assert.equal(await kind(() => Response.json(window("2026-12-03T00:00:00Z", "2026-12-01T00:00:00Z"))), "invalid");
  assert.equal(await kind(() => Response.json(window("2026-12-01T00:00:00Z", "2026-12-01T00:00:00Z"))), "invalid");
  assert.equal(await kind(() => Response.json({ suggestedWindow: { start: "2026-12-01T00:00:00Z" } })), "invalid");
  assert.equal(await kind(() => Response.json(window("soon", "later"))), "invalid");
  await assert.rejects(renewalInfo(DIRECTORY, "id", NOW, fakeCa(() => new Response("", { status: 500 })).fetch), /HTTP 500/);
});

test("reads Retry-After as seconds or as an HTTP date", () => {
  assert.equal(retryAfter("21600", NOW), 21600);
  assert.equal(retryAfter(" 60 ", NOW), 60);
  assert.equal(retryAfter("Wed, 11 Nov 2026 13:00:00 GMT", NOW), 3600);
  assert.equal(retryAfter("Wed, 11 Nov 2026 11:00:00 GMT", NOW), 0);
  assert.equal(retryAfter("soon", NOW), undefined);
  assert.equal(retryAfter(null, NOW), undefined);
});

test("is due once the suggested window opens, and overdue after it closes", () => {
  const notBefore = new Date("2026-10-01T00:00:00Z");
  const notAfter = new Date("2026-12-30T00:00:00Z");
  const info: RenewalInfo = { kind: "window", start: new Date("2026-11-20T00:00:00Z"), end: new Date("2026-11-22T00:00:00Z") };
  const at = (iso: string) => plan(new Date(iso), notBefore, notAfter, info).status;
  assert.equal(at("2026-11-19T23:59:59Z"), "scheduled");
  assert.equal(at("2026-11-20T00:00:00Z"), "due");
  assert.equal(at("2026-11-21T23:59:59Z"), "due");
  assert.equal(at("2026-11-22T00:00:00Z"), "overdue");
  assert.equal(at("2026-12-30T00:00:00Z"), "expired");
  assert.equal(plan(NOW, notBefore, notAfter, info).source, "ari");
});

test("falls back to two thirds of the lifetime when there is no usable window", () => {
  const notBefore = new Date("2026-10-01T00:00:00Z");
  const notAfter = new Date("2026-12-30T00:00:00Z"); // 90 days: two thirds is 60 days in
  for (const info of [undefined, { kind: "unknown" } as const, { kind: "invalid", reason: "x" } as const]) {
    const p = plan(new Date("2026-11-29T23:59:59Z"), notBefore, notAfter, info);
    assert.equal(p.source, "fallback");
    assert.deepEqual(p.from, new Date("2026-11-30T00:00:00Z"));
    assert.equal(p.status, "scheduled");
    assert.equal(plan(new Date("2026-11-30T00:00:00Z"), notBefore, notAfter, info).status, "due");
  }
});

test("knows the ACME directories of CAs that publish renewal information", () => {
  assert.equal(directoryFor("Let's Encrypt"), "https://acme-v02.api.letsencrypt.org/directory");
  assert.equal(directoryFor("Google Trust Services"), "https://dv.acme-v02.api.pki.goog/directory");
  assert.equal(directoryFor("Google Trust Services LLC"), "https://dv.acme-v02.api.pki.goog/directory");
  assert.equal(directoryFor("ZeroSSL"), "https://acme.zerossl.com/v2/DV90");
  assert.equal(directoryFor("Sectigo Limited"), undefined);
  assert.equal(directoryFor(undefined), undefined);
});
