#!/usr/bin/env node
// ari-check: reads each host's TLS certificate, or a certificate file, and asks the issuing CA
// when to renew it, using ACME Renewal Information (RFC 9773). Exits 1 if any certificate should
// be renewed now and 2 if one couldn't be checked, so it can run from cron or a monitoring check.

import { parseArgs } from "node:util";

import { check, checkFile, describe } from "./check.ts";

const USAGE = "usage: ari-check [--json] [--directory ACME_DIRECTORY_URL] [--file CERT_FILE]... [host[:port]]...";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    json: { type: "boolean" },
    directory: { type: "string" },
    file: { type: "string", multiple: true, default: [] },
    help: { type: "boolean", short: "h" },
  },
});

if (values.help || positionals.length + values.file.length === 0) {
  console.error(USAGE);
  process.exitCode = values.help ? 0 : 2;
} else {
  const now = new Date();
  const options = { directory: values.directory, now };
  const results = await Promise.all([
    ...positionals.map((target) => check(target, options)),
    ...values.file.map((path) => checkFile(path, options)),
  ]);
  console.log(values.json ? JSON.stringify(results, null, 2) : results.map((result) => describe(result, now)).join("\n\n"));
  // Not process.exit(): it can trip a libuv assertion on Windows.
  process.exitCode = Math.max(
    0,
    ...results.map((result) => (result.error ? 2 : result.plan?.status === "scheduled" ? 0 : 1)),
  );
}
