// Asking the CA when to renew (RFC 9773): find the renewalInfo URL in its ACME directory, fetch
// the suggested window for a certificate, and turn that into a plan.

const TIMEOUT_MS = 10_000;

/** ACME directories of CAs that publish renewal information, by the issuer's organization. */
export const DIRECTORIES: [organization: string, directory: string][] = [
  ["Let's Encrypt", "https://acme-v02.api.letsencrypt.org/directory"],
  ["Google Trust Services", "https://dv.acme-v02.api.pki.goog/directory"],
  ["ZeroSSL", "https://acme.zerossl.com/v2/DV90"],
];

export function directoryFor(issuerOrganization: string | undefined): string | undefined {
  return DIRECTORIES.find(([organization]) => issuerOrganization?.startsWith(organization))?.[1];
}

export type RenewalInfo =
  | { kind: "window"; start: Date; end: Date; explanationURL?: string; retryAfterSeconds?: number }
  /** The CA's directory has no renewalInfo. */
  | { kind: "unsupported" }
  /** The CA doesn't know this certificate, for example one it didn't issue through ACME. */
  | { kind: "unknown" }
  /** A reply the RFC says to treat as no reply at all, such as a window that ends before it starts. */
  | { kind: "invalid"; reason: string };

type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

function time(value: unknown): Date | undefined {
  const at = typeof value === "string" ? Date.parse(value) : Number.NaN;
  return Number.isNaN(at) ? undefined : new Date(at);
}

/** Retry-After as seconds from now: either a number of seconds or an HTTP date. */
export function retryAfter(header: string | null, now: Date): number | undefined {
  if (!header) return undefined;
  if (/^\d+$/.test(header.trim())) return Number(header);
  const at = Date.parse(header);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.round((at - now.getTime()) / 1000));
}

export async function renewalInfo(directoryUrl: string, id: string, now: Date, fetchImpl: Fetch = fetch): Promise<RenewalInfo> {
  // A 404 is an answer only from renewalInfo, where it means the CA doesn't know the certificate.
  const get = async (url: string, notFoundIsAnswer: boolean) => {
    const response = await fetchImpl(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!response.ok && !(notFoundIsAnswer && response.status === 404)) throw new Error(`${url}: HTTP ${response.status}`);
    return response;
  };
  const directory = (await (await get(directoryUrl, false)).json()) as { renewalInfo?: unknown };
  if (typeof directory.renewalInfo !== "string") return { kind: "unsupported" };

  const response = await get(`${directory.renewalInfo.replace(/\/$/, "")}/${id}`, true);
  if (response.status === 404) return { kind: "unknown" };
  const body = (await response.json()) as { suggestedWindow?: { start?: unknown; end?: unknown }; explanationURL?: unknown };
  const start = time(body.suggestedWindow?.start);
  const end = time(body.suggestedWindow?.end);
  if (!start || !end) return { kind: "invalid", reason: "no suggestedWindow with a start and an end" };
  if (end <= start) return { kind: "invalid", reason: "the suggested window ends before it starts" };
  return {
    kind: "window",
    start,
    end,
    explanationURL: typeof body.explanationURL === "string" ? body.explanationURL : undefined,
    retryAfterSeconds: retryAfter(response.headers.get("retry-after"), now),
  };
}

export type Status = "scheduled" | "due" | "overdue" | "expired";

export interface Plan {
  status: Status;
  /** When to renew: the CA's suggested window, or a fallback when there is none. */
  from: Date;
  until: Date;
  source: "ari" | "fallback";
}

/**
 * The RFC's advice is to renew at a random moment inside the window, and at once if that moment
 * has passed, so a certificate is due as soon as the window opens. Without a window, the fallback
 * is the usual rule of renewing once two thirds of the lifetime are gone.
 */
export function plan(now: Date, notBefore: Date, notAfter: Date, info: RenewalInfo | undefined): Plan {
  const lifetime = notAfter.getTime() - notBefore.getTime();
  const window =
    info?.kind === "window"
      ? { from: info.start, until: info.end, source: "ari" as const }
      : { from: new Date(notBefore.getTime() + (lifetime * 2) / 3), until: notAfter, source: "fallback" as const };
  const status: Status =
    now >= notAfter ? "expired" : now < window.from ? "scheduled" : now < window.until ? "due" : "overdue";
  return { status, ...window };
}
