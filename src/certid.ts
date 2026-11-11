// The certificate identifier ARI uses (RFC 9773 section 4.1): the base64url of the Authority Key
// Identifier's keyIdentifier, a period, and the base64url of the serial number's DER bytes,
// leading zero included. Only those two fields are read, with a small DER reader of our own.

interface Tlv {
  tag: number;
  start: number; // first content byte
  end: number; // one past the last content byte
}

function read(der: Uint8Array, at: number): Tlv {
  const tag = der[at];
  let length = der[at + 1];
  if (tag === undefined || length === undefined) throw new Error("truncated DER");
  if ((tag & 0x1f) === 0x1f) throw new Error("unexpected multi-byte DER tag");
  let start = at + 2;
  if (length & 0x80) {
    const bytes = length & 0x7f;
    if (bytes === 0 || bytes > 4) throw new Error("unsupported DER length");
    length = 0;
    for (let i = 0; i < bytes; i++) {
      const byte = der[start + i];
      if (byte === undefined) throw new Error("truncated DER");
      length = length * 256 + byte;
    }
    start += bytes;
  }
  const end = start + length;
  if (end > der.length) throw new Error("truncated DER");
  return { tag, start, end };
}

function children(der: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let at = parent.start; at < parent.end; ) {
    const child = read(der, at);
    if (child.end > parent.end) throw new Error("DER element overruns its parent");
    out.push(child);
    at = child.end;
  }
  return out;
}

const SEQUENCE = 0x30;
const INTEGER = 0x02;
const OID = 0x06;
const OCTET_STRING = 0x04;
const VERSION = 0xa0; // [0] EXPLICIT
const EXTENSIONS = 0xa3; // [3] EXPLICIT
const KEY_IDENTIFIER = 0x80; // [0] IMPLICIT OCTET STRING
const AUTHORITY_KEY_IDENTIFIER = Uint8Array.of(0x55, 0x1d, 0x23); // 2.5.29.35

const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** The ARI certificate identifier of a DER-encoded certificate. */
export function certId(der: Uint8Array): string {
  const certificate = read(der, 0);
  if (certificate.tag !== SEQUENCE || certificate.end !== der.length) throw new Error("not a DER certificate");
  const tbs = children(der, certificate)[0];
  if (tbs?.tag !== SEQUENCE) throw new Error("not a DER certificate");
  const fields = children(der, tbs);
  const serial = fields[fields[0]?.tag === VERSION ? 1 : 0];
  if (serial?.tag !== INTEGER) throw new Error("certificate has no serial number");

  const extensions = fields.find((field) => field.tag === EXTENSIONS);
  if (!extensions) throw new Error("certificate has no Authority Key Identifier");
  const [list] = children(der, extensions);
  if (list?.tag !== SEQUENCE) throw new Error("malformed certificate extensions");
  for (const extension of children(der, list)) {
    const parts = children(der, extension);
    const oid = parts[0];
    if (oid?.tag !== OID || !same(der.subarray(oid.start, oid.end), AUTHORITY_KEY_IDENTIFIER)) continue;
    const value = parts[parts.length - 1]; // the OCTET STRING, after an optional critical flag
    if (value?.tag !== OCTET_STRING) throw new Error("malformed Authority Key Identifier");
    const keyIdentifier = children(der, read(der, value.start)).find((part) => part.tag === KEY_IDENTIFIER);
    if (!keyIdentifier) throw new Error("Authority Key Identifier has no keyIdentifier");
    return `${base64url(der.subarray(keyIdentifier.start, keyIdentifier.end))}.${base64url(der.subarray(serial.start, serial.end))}`;
  }
  throw new Error("certificate has no Authority Key Identifier");
}
