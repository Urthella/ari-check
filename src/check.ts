// Checks one host: reads the certificate it serves, asks the issuing CA for a renewal window when
// it publishes one, and describes the result.

import { X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import { connect } from "node:tls";

import { type Plan, type RenewalInfo, directoryFor, plan, renewalInfo } from "./ari.ts";
import { certId } from "./certid.ts";

const TIMEOUT_MS = 10_000;
const DAY_MS = 86_400_000;

export interface Result {
  target: string;
  error?: string;
  subject?: string;
  issuer?: string;
  notBefore?: Date;
  notAfter?: Date;
  /** Whether the chain verifies against this machine's trust store. */
  trusted?: boolean;
  certId?: string;
  ari?: RenewalInfo;
  plan?: Plan;
}

export interface Options {
  /** An ACME directory to ask for every host, instead of looking one up by issuer. */
  directory?: string;
  now?: Date;
  fetch?: (url: string, init?: RequestInit) => Promise<Response>;
}

export function parseTarget(target: string): { host: string; port: number } {
  const match = /^\[([^\]]+)\](?::(\d+))?$/.exec(target) ?? /^([^:[\]]+)(?::(\d+))?$/.exec(target);
  const port = Number(match?.[2] ?? 443);
  if (!match || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`not a host or host:port: ${target}`);
  return { host: match[1], port };
}

function fetchCertificate(host: string, port: number): Promise<{ der: Buffer; trusted: boolean }> {
  return new Promise((resolve, reject) => {
    // Untrusted chains are still read: an expired or misconfigured certificate is worth reporting.
    const socket = connect({ host, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: TIMEOUT_MS }, () => {
      const certificate = socket.getPeerCertificate();
      socket.end();
      if (!certificate?.raw) reject(new Error("the server sent no certificate"));
      else resolve({ der: certificate.raw, trusted: socket.authorized });
    });
    socket.on("timeout", () => socket.destroy(new Error("timed out")));
    socket.on("error", reject);
  });
}

/** One attribute of a distinguished name as Node prints it, one "KEY=value" per line. */
function attribute(name: string, key: string): string | undefined {
  return name.split("\n").find((line) => line.startsWith(`${key}=`))?.slice(key.length + 1);
}

export async function check(target: string, options: Options = {}): Promise<Result> {
  const now = options.now ?? new Date();
  try {
    const { host, port } = parseTarget(target);
    const { der, trusted } = await fetchCertificate(host, port);
    const x509 = new X509Certificate(der);
    const notBefore = x509.validFromDate;
    const notAfter = x509.validToDate;
    const issuerOrganization = attribute(x509.issuer, "O");
    const result: Result = {
      target,
      subject: attribute(x509.subject, "CN") ?? x509.subjectAltName ?? "",
      issuer: [issuerOrganization, attribute(x509.issuer, "CN")].filter(Boolean).join(" "),
      notBefore,
      notAfter,
      trusted,
    };
    const directory = options.directory ?? directoryFor(issuerOrganization);
    // RFC 9773 section 4.3: never ask about a certificate that has already expired.
    if (directory && now < notAfter) {
      result.certId = certId(der);
      result.ari = await renewalInfo(directory, result.certId, now, options.fetch);
    }
    result.plan = plan(now, notBefore, notAfter, result.ari);
    return result;
  } catch (error) {
    return { target, error: (error as Error).message };
  }
}

const when = (date: Date) => date.toISOString().slice(0, 16).replace("T", " ") + " UTC";

const VERDICT = {
  scheduled: "not yet",
  due: "renew now",
  overdue: "renew now, the window has passed",
  expired: "expired",
} as const;

/** A few lines describing a result for a person. */
export function describe(result: Result, now: Date): string {
  if (result.error || !result.plan || !result.notBefore || !result.notAfter) return `${result.target}  error: ${result.error}`;
  const lifetime = Math.round((result.notAfter.getTime() - result.notBefore.getTime()) / DAY_MS);
  const left = Math.floor((result.notAfter.getTime() - now.getTime()) / DAY_MS);
  const lines = [
    `${result.target}  ${result.subject}, issued by ${result.issuer}${result.trusted ? "" : " (not trusted here)"}`,
    `  ${lifetime}-day certificate, ${left >= 0 ? `expires ${when(result.notAfter)}, in ${left} days` : `expired ${when(result.notAfter)}`}`,
  ];
  const { from, until, status } = result.plan;
  const ari = result.ari;
  if (status === "expired") lines.push(`  ${VERDICT.expired}`);
  else if (ari?.kind === "window") {
    const again = ari.retryAfterSeconds === undefined ? "" : `; the CA asks to check again in ${Math.round(ari.retryAfterSeconds / 3600)} h`;
    lines.push(`  CA suggests renewing between ${when(from)} and ${when(until)}: ${VERDICT[status]}${again}`);
    if (ari.explanationURL) lines.push(`  why: ${ari.explanationURL}`);
  } else {
    const reason =
      ari?.kind === "unknown" ? "the CA has no renewal information for this certificate"
      : ari?.kind === "invalid" ? `the CA's reply was ignored: ${ari.reason}`
      : "this CA doesn't publish renewal information";
    lines.push(`  ${reason}; renew once two thirds of its lifetime have passed, from ${when(from)}: ${VERDICT[status]}`);
  }
  return lines.join("\n");
}
