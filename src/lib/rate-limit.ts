// In-memory sliding-window rate limiter. Good enough to stop casual abuse of a
// hackathon demo deployment (e.g. someone scripting requests against a public
// URL and burning through the Anthropic API budget); it is NOT a substitute for
// a real rate limiter (Redis/Upstash) in a multi-instance production deploy,
// since each serverless instance would keep its own counters.
const buckets = new Map<string, { count: number; resetAt: number }>();

export type RateLimitResult = { allowed: boolean; retryAfterMs: number };

export function checkRateLimit(key: string, limit: number, windowMs: number): RateLimitResult {
  const now = Date.now();
  const bucket = buckets.get(key);

  if (!bucket || now >= bucket.resetAt) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfterMs: 0 };
  }

  if (bucket.count >= limit) {
    return { allowed: false, retryAfterMs: bucket.resetAt - now };
  }

  bucket.count += 1;
  return { allowed: true, retryAfterMs: 0 };
}

export function clientKey(req: Request): string {
  const forwardedFor = req.headers.get("x-forwarded-for");
  return forwardedFor?.split(",")[0]?.trim() || "unknown";
}
