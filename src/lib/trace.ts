import dns from "node:dns/promises";
import net from "node:net";

export type TraceHop = {
  url: string;
  status: number | null;
  note?: string;
};

export type TraceResult = {
  hops: TraceHop[];
  finalUrl: string | null;
  blocked: boolean;
  blockedReason?: string;
};

const MAX_HOPS = 8;
const HOP_TIMEOUT_MS = 5000;

function isForbiddenIp(ip: string): boolean {
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    return (
      lower === "::1" ||
      lower.startsWith("fc") ||
      lower.startsWith("fd") ||
      lower.startsWith("fe80") ||
      lower.startsWith("::ffff:127.") ||
      lower.startsWith("::ffff:10.") ||
      lower.startsWith("::ffff:192.168.") ||
      lower.startsWith("::ffff:169.254.")
    );
  }
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return true;
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224
  );
}

async function checkUrlAllowed(url: URL): Promise<string | null> {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return `Scheme "${url.protocol}" is not allowed.`;
  }
  const hostname = url.hostname;
  if (net.isIP(hostname)) {
    return isForbiddenIp(hostname) ? "Destination resolves to a private or internal address." : null;
  }
  try {
    const records = await dns.lookup(hostname, { all: true });
    for (const r of records) {
      if (isForbiddenIp(r.address)) {
        return "Destination resolves to a private or internal address.";
      }
    }
    return null;
  } catch {
    return "Hostname does not resolve.";
  }
}

export async function traceUrl(startUrl: string): Promise<TraceResult> {
  const hops: TraceHop[] = [];
  let current: string = startUrl;

  for (let i = 0; i < MAX_HOPS; i++) {
    let parsed: URL;
    try {
      parsed = new URL(current);
    } catch {
      hops.push({ url: current, status: null, note: "Invalid URL" });
      return { hops, finalUrl: null, blocked: true, blockedReason: "Invalid URL in redirect chain." };
    }

    const forbidden = await checkUrlAllowed(parsed);
    if (forbidden) {
      hops.push({ url: current, status: null, note: forbidden });
      return { hops, finalUrl: null, blocked: true, blockedReason: forbidden };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), HOP_TIMEOUT_MS);
    try {
      const res = await fetch(current, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { "user-agent": "PhishLens-LinkTracer/1.0 (+security-analysis)" },
      });
      clearTimeout(timer);

      const location = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && location) {
        hops.push({ url: current, status: res.status });
        current = new URL(location, current).toString();
        continue;
      }

      hops.push({ url: current, status: res.status });
      return { hops, finalUrl: current, blocked: false };
    } catch (err) {
      clearTimeout(timer);
      const timedOut = err instanceof Error && err.name === "AbortError";
      hops.push({ url: current, status: null, note: timedOut ? "Timed out" : "Connection failed" });
      return { hops, finalUrl: null, blocked: false };
    }
  }

  return {
    hops,
    finalUrl: null,
    blocked: true,
    blockedReason: `Stopped after ${MAX_HOPS} redirects — excessive redirect chains are themselves suspicious.`,
  };
}
