# ari-check

Ask the CA when to renew. `ari-check` reads the certificate each host serves, and fetches the
renewal window its CA suggests through ACME Renewal Information (ARI,
[RFC 9773](https://www.rfc-editor.org/rfc/rfc9773)). It exits 1 when a certificate should be
renewed now, so it fits a cron job or a monitoring check.

## Why

Certificates are getting shorter-lived. Under the CA/Browser Forum's ballot SC-081, a public TLS
certificate may last at most 200 days from 15 March 2026, 100 days from 15 March 2027, and 47
days from 15 March 2029.

With ARI, the CA itself says when to renew. It can also ask for an earlier renewal when it needs
one, for example ahead of revoking certificates after an incident, which is the RFC's own
example. ACME clients that support ARI follow this automatically. `ari-check` shows it for any
host, including certificates renewed by a platform or a client you don't control.

## Quick start

Needs Node 24 or later, and nothing else.

```sh
git clone https://github.com/Urthella/ari-check && cd ari-check
node src/main.ts letsencrypt.org www.google.com github.com
```

```text
letsencrypt.org  letsencrypt.org, issued by Let's Encrypt YE2
  90-day certificate, expires 2027-02-01 13:44 UTC, in 82 days
  CA suggests renewing between 2027-01-01 16:28 UTC and 2027-01-03 11:39 UTC: not yet; the CA asks to check again in 6 h

www.google.com  www.google.com, issued by Google Trust Services WE2
  84-day certificate, expires 2026-12-30 19:09 UTC, in 49 days
  CA suggests renewing between 2026-11-26 13:44 UTC and 2026-11-26 14:44 UTC: not yet; the CA asks to check again in 8 h
  why: https://status.pki.goog/

github.com  github.com, issued by Sectigo Limited Sectigo Public Server Authentication CA DV E36
  90-day certificate, expires 2027-01-27 23:59 UTC, in 77 days
  this CA doesn't publish renewal information; renew once two thirds of its lifetime have passed, from 2026-12-28 23:59 UTC: not yet
```

Hosts can carry a port, as `host:443` or `[::1]:8443`.

`--file PATH` checks a certificate file instead of a live host. This works for a certificate
your ACME client just wrote, before the server reloads it, or for a service that doesn't speak
TLS from the first byte. The file can be PEM, where the first certificate is used, as the leaf
comes first in a chain, or DER. Repeat the flag for more files:

```sh
node src/main.ts --file /etc/letsencrypt/live/example.com/fullchain.pem
```

`--json` prints the results as JSON. `--directory URL` asks that ACME directory for every
certificate, which is useful for a CA the tool doesn't know.

The exit code:

| Code | Meaning |
|---|---|
| 0 | Every certificate is fine for now. |
| 1 | At least one is due, past its window, or expired. |
| 2 | At least one host couldn't be checked. |

## What it does

1. **Reads the certificate.** It connects with TLS and SNI and reads the certificate the host
   serves. It reads it even when the chain doesn't verify on this machine, and says so.
2. **Builds the certificate's ARI ID.** That's the base64url of the Authority Key Identifier's
   `keyIdentifier`, a period, and the base64url of the serial number's DER bytes. A small DER
   reader of its own does this.
3. **Finds the CA's ACME directory** from the issuer: Let's Encrypt, Google Trust Services or
   ZeroSSL. On 2026-11-11 these advertised `renewalInfo`, and so did SSL.com, which has a
   directory per key type and needs `--directory`.
4. **Fetches the suggested window**, its `explanationURL` and its `Retry-After`.
   - A window that ends before it starts is ignored, as the RFC requires.
   - A 404 means the CA doesn't know the certificate.
   - An expired certificate is never asked about (§4.3).
5. **Makes a plan.** The RFC recommends renewing at a random moment inside the window, and at
   once if that moment has passed. So a certificate is **due** as soon as the window opens, and
   **overdue** once it closes. Without a usable window it falls back to the usual rule: renew
   once two thirds of the lifetime have passed.

## How it's checked

- **The RFC's own example.** The example certificate in RFC 9773 Appendix A gives
  `aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE`, as the RFC says it should.
- **An independent parser.** For real certificates from Let's Encrypt and Google Trust Services,
  and for a test PKI from [`scripts/make-fixtures.sh`](scripts/make-fixtures.sh), the IDs agree
  with [`@peculiar/x509`](https://github.com/PeculiarVentures/x509). The cases include a serial
  that needs a leading zero byte, a version 1 certificate, and a certificate without an AKI.
  Truncated DER, an element that overruns its parent, and trailing bytes are all refused.
- **The ARI client against a fake CA.** The tests cover the request URL, unknown certificates,
  CAs without ARI, invalid windows, both forms of `Retry-After`, and HTTP errors.
- **End to end.** The CLI runs against a local TLS server and a fake ACME server that only
  answers for the right ID:
  - a window that hasn't opened gives exit 0;
  - an open window gives 1;
  - an unknown certificate falls back to the lifetime rule;
  - an expired certificate gives 1, and the CA is never asked about it;
  - a PEM chain file is read by its first certificate, and a DER file works too;
  - unreachable hosts, unreadable files and bad arguments give 2.
- **Mutation testing.** Twenty-five deliberate bugs were planted one at a time, and the tests
  caught every one.
- **Live**, with `npm run crosscheck`. Six hosts, served by Let's Encrypt and Google Trust
  Services, were checked:
  - every ID matched the independent parser;
  - both CAs recognized every ID;
  - each returned a window that lies inside the certificate's validity.

## Limits

- It checks one certificate per host, the one served for its name. There's no STARTTLS; use
  `--file` for those certificates.
- Only the CAs above are known by name. Others need `--directory`.
- It tells you when to renew; it doesn't renew anything.

## License

MIT
