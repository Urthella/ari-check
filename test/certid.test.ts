import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import "reflect-metadata"; // @peculiar/x509 needs it loaded first
import * as x509 from "@peculiar/x509";

import { certId } from "../src/certid.ts";

const pem = (name: string) => readFileSync(new URL(`fixtures/${name}.pem`, import.meta.url), "utf8");
const der = (name: string) => new Uint8Array(new x509.X509Certificate(pem(name)).rawData);

/** The CertID worked out with a second, independent X.509 parser. */
function expected(name: string): string {
  const certificate = new x509.X509Certificate(pem(name));
  const aki = certificate.getExtension(x509.AuthorityKeyIdentifierExtension);
  assert.ok(aki?.keyId, `${name} has an Authority Key Identifier`);
  // The serial's DER value bytes: no redundant leading zeros, but a zero in front of a high bit.
  let serial = Buffer.from(certificate.serialNumber.padStart(2, "0"), "hex");
  while (serial.length > 1 && serial[0] === 0 && serial[1] < 0x80) serial = serial.subarray(1);
  if (serial[0] >= 0x80) serial = Buffer.concat([Buffer.of(0), serial]);
  return `${Buffer.from(aki.keyId, "hex").toString("base64url")}.${serial.toString("base64url")}`;
}

test("matches the example in RFC 9773 section 4.1", () => {
  assert.equal(certId(der("rfc9773-example")), "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE");
});

test("agrees with an independent parser on real and test certificates", () => {
  for (const name of ["letsencrypt.org", "www.google.com", "localhost", "rfc9773-example"]) {
    assert.equal(certId(der(name)), expected(name), name);
  }
});

test("keeps the leading zero a serial with its high bit set needs", () => {
  // The test certificate's serial is 0x87654321abcdef.
  assert.equal(certId(der("localhost")).split(".")[1], Buffer.from("0087654321abcdef", "hex").toString("base64url"));
});

test("refuses certificates without an Authority Key Identifier, and things that aren't certificates", () => {
  assert.throws(() => certId(der("no-aki")), /no Authority Key Identifier/);
  // A version 1 certificate has no version field, so its serial comes first; it has no extensions.
  assert.throws(() => certId(der("v1")), /no Authority Key Identifier/);
  const good = der("localhost");
  assert.throws(() => certId(good.subarray(0, good.length - 10)), /truncated|not a DER certificate/);
  assert.throws(() => certId(Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x01)), /no serial number|not a DER certificate/);
  assert.throws(() => certId(Uint8Array.of()), /truncated/);
  assert.throws(() => certId(Uint8Array.of(0x30, 0x85, 1, 2, 3, 4, 5)), /unsupported DER length/);
  // A server's bytes are untrusted: an element may not run past its parent, even when the
  // buffer has room, and nothing may follow the certificate.
  const overrun = Uint8Array.of(0x30, 0x08, 0x30, 0x02, 0x02, 0x04, 0x05, 0x00, 0x05, 0x00);
  assert.throws(() => certId(overrun), /overruns its parent/);
  assert.throws(() => certId(Uint8Array.of(...good, 0x00)), /not a DER certificate/);
});
