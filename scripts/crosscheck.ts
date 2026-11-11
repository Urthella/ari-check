// Live check against real CAs: `npm run crosscheck`. For each host, the certificate ID must match
// what an independent X.509 parser gives, the issuing CA must recognize that ID (a 200 with a
// window rather than a 404), and the window must lie inside the certificate's validity.

import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { connect } from "node:tls";

import { directoryFor, renewalInfo } from "../src/ari.ts";
import { certId } from "../src/certid.ts";

const HOSTS = ["letsencrypt.org", "eff.org", "community.letsencrypt.org", "www.google.com", "www.youtube.com", "go.dev"];

function leaf(host: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host, port: 443, servername: host, timeout: 10_000 }, () => {
      resolve(socket.getPeerCertificate().raw);
      socket.end();
    });
    socket.on("error", reject);
  });
}

function independentId(der: Buffer): string {
  const certificate = new x509.X509Certificate(der);
  const keyId = certificate.getExtension(x509.AuthorityKeyIdentifierExtension)?.keyId ?? "";
  let serial = Buffer.from(certificate.serialNumber.padStart(2, "0"), "hex");
  while (serial.length > 1 && serial[0] === 0 && serial[1] < 0x80) serial = serial.subarray(1);
  if (serial[0] >= 0x80) serial = Buffer.concat([Buffer.of(0), serial]);
  return `${Buffer.from(keyId, "hex").toString("base64url")}.${serial.toString("base64url")}`;
}

let failed = 0;
const report = (ok: boolean, line: string) => {
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"} ${line}`);
};

const now = new Date();
for (const host of HOSTS) {
  const der = await leaf(host);
  const certificate = new x509.X509Certificate(der);
  const issuer = /O=([^,]+)/.exec(certificate.issuer)?.[1];
  const ours = certId(der);
  report(ours === independentId(der), `${host}: certificate ID ${ours} matches the independent parser`);
  const directory = directoryFor(issuer);
  if (!directory) {
    console.log(`skip ${host}: issued by ${issuer}, which has no known ACME directory`);
    continue;
  }
  const info = await renewalInfo(directory, ours, now);
  if (info.kind !== "window") {
    report(false, `${host}: ${issuer} answered ${info.kind}`);
    continue;
  }
  const inside = info.start >= certificate.notBefore && info.end <= certificate.notAfter;
  report(inside, `${host}: ${issuer} suggests ${info.start.toISOString()} to ${info.end.toISOString()}, inside the certificate's validity`);
}
if (failed) {
  console.log(`${failed} check(s) failed`);
  process.exitCode = 1;
}
