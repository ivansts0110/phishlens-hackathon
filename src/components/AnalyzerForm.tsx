"use client";

import { useState } from "react";
import { SAMPLES } from "@/lib/samples";
import { RiskGauge } from "./RiskGauge";
import type { Indicator } from "@/lib/phishing-engine";

type AnalyzeResponse = {
  result: { score: number; level: string; indicators: Indicator[]; urls: string[] };
  aiExplanation?: string;
  aiStatus?: "disabled" | "ok" | "timeout" | "error";
};

const CATEGORY_LABEL: Record<string, string> = {
  sender: "Sender",
  links: "Links",
  content: "Content",
  urgency: "Urgency",
};

export function AnalyzerForm() {
  const [org, setOrg] = useState("Acme Corp");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<AnalyzeResponse | null>(null);

  function loadSample(key: string) {
    const sample = SAMPLES.find((s) => s.key === key);
    if (!sample) return;
    setOrg(sample.org);
    setSender(sample.sender);
    setSubject(sample.subject);
    setBody(sample.body);
    setData(null);
    setError(null);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ org, sender, subject, body }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error ?? "Analysis failed");
      }
      const record = await res.json();
      setData({ result: record.result, aiExplanation: record.aiExplanation, aiStatus: record.aiStatus });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid gap-8 lg:grid-cols-2">
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div className="flex flex-wrap gap-2">
          {SAMPLES.map((s) => (
            <button
              key={s.key}
              type="button"
              onClick={() => loadSample(s.key)}
              className="border border-black/30 px-3 py-1.5 text-xs font-medium hover:bg-black/5 dark:border-white/30 dark:hover:bg-white/10"
            >
              {s.label}
            </button>
          ))}
        </div>

        <label className="flex flex-col gap-1.5 text-sm">
          <span className="font-medium">Organization</span>
          <input
            value={org}
            onChange={(e) => setOrg(e.target.value)}
            placeholder="Acme Corp"
            className="border border-black/30 bg-transparent px-3 py-2 outline-none focus:border-black dark:border-white/30 dark:focus:border-white"
          />
        </label>

        <label className="flex flex-col gap-1.5 text-sm">
          <span className="font-medium">Sender</span>
          <input
            value={sender}
            onChange={(e) => setSender(e.target.value)}
            placeholder="Display Name <address@domain.com>"
            className="border border-black/30 bg-transparent px-3 py-2 outline-none focus:border-black dark:border-white/30 dark:focus:border-white"
          />
        </label>

        <label className="flex flex-col gap-1.5 text-sm">
          <span className="font-medium">Subject</span>
          <input
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="Email subject line"
            className="border border-black/30 bg-transparent px-3 py-2 outline-none focus:border-black dark:border-white/30 dark:focus:border-white"
          />
        </label>

        <label className="flex flex-col gap-1.5 text-sm">
          <span className="font-medium">Message body</span>
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            required
            rows={10}
            placeholder="Paste the full email or message text here..."
            className="border border-black/30 bg-transparent px-3 py-2 font-mono text-xs outline-none focus:border-black dark:border-white/30 dark:focus:border-white"
          />
        </label>

        <button
          type="submit"
          disabled={loading}
          className="border border-black bg-black px-4 py-2.5 font-medium text-white hover:bg-black/80 disabled:opacity-50 dark:border-white dark:bg-white dark:text-black dark:hover:bg-white/80"
        >
          {loading ? "Analyzing…" : "Analyze message"}
        </button>
        {error && <p className="text-sm text-red-700 dark:text-red-400">{error}</p>}
      </form>

      <div className="flex flex-col gap-4">
        {!data && (
          <div className="flex h-full min-h-72 flex-col items-center justify-center border border-dashed border-black/30 p-8 text-center text-sm text-black/60 dark:border-white/30 dark:text-white/60">
            Paste a message (or load a sample) and click Analyze to see the risk breakdown.
          </div>
        )}

        {data && (
          <>
            <div className="flex items-center justify-center border border-black/30 p-6 dark:border-white/30">
              <RiskGauge score={data.result.score} level={data.result.level} />
            </div>

            {data.aiExplanation && (
              <div className="border border-black/30 p-4 dark:border-white/30">
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide">AI summary</p>
                <p className="whitespace-pre-line text-sm">{data.aiExplanation}</p>
              </div>
            )}

            {(data.aiStatus === "timeout" || data.aiStatus === "error") && (
              <p className="text-xs text-black/50 dark:text-white/50">
                AI summary unavailable ({data.aiStatus === "timeout" ? "request timed out" : "service error"}) —
                showing heuristic results only.
              </p>
            )}

            <div className="border border-black/30 dark:border-white/30">
              <p className="border-b border-black/30 px-4 py-3 text-sm font-semibold dark:border-white/30">
                Detected indicators {data.result.indicators.length === 0 && "— none"}
              </p>
              <ul className="divide-y divide-black/15 dark:divide-white/15">
                {data.result.indicators.map((ind) => (
                  <li key={ind.id} className="flex items-start gap-3 px-4 py-3">
                    <span className="mt-0.5 shrink-0 border border-black/30 px-1.5 py-0.5 text-[11px] font-medium dark:border-white/30">
                      {CATEGORY_LABEL[ind.category]}
                    </span>
                    <div className="text-sm">
                      <p className="font-medium">{ind.label}</p>
                      <p className="text-black/60 dark:text-white/60">{ind.detail}</p>
                    </div>
                    <span className="ml-auto shrink-0 text-xs font-semibold text-black/50 dark:text-white/50">
                      +{ind.weight}
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            {data.result.urls.length > 0 && (
              <div className="border border-black/30 p-4 dark:border-white/30">
                <p className="mb-2 text-sm font-semibold">Extracted links</p>
                <ul className="space-y-1 font-mono text-xs text-black/60 dark:text-white/60">
                  {data.result.urls.map((u) => (
                    <li key={u} className="break-all">
                      {u}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
