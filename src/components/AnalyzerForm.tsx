"use client";

import { useRef, useState } from "react";
import { SAMPLES } from "@/lib/samples";
import { RiskGauge } from "./RiskGauge";
import type { Indicator } from "@/lib/phishing-engine";
import type { HeaderReport } from "@/lib/header-analysis";

type AnalyzeResponse = {
  id: string;
  result: { score: number; level: string; indicators: Indicator[]; urls: string[] };
  aiExplanation?: string;
  aiStatus?: "disabled" | "ok" | "timeout" | "error";
  headerReport?: HeaderReport;
};

type TraceHop = { url: string; status: number | null; note?: string };
type TraceState =
  | { state: "loading" }
  | { state: "done"; hops: TraceHop[]; finalUrl: string | null; blocked: boolean; blockedReason?: string }
  | { state: "error"; message: string };

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
  const [emlContent, setEmlContent] = useState<string | null>(null);
  const [emlName, setEmlName] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<AnalyzeResponse | null>(null);
  const [traces, setTraces] = useState<Record<string, TraceState>>({});
  const fileInputRef = useRef<HTMLInputElement>(null);

  function loadSample(key: string) {
    const sample = SAMPLES.find((s) => s.key === key);
    if (!sample) return;
    clearEml();
    setOrg(sample.org);
    setSender(sample.sender);
    setSubject(sample.subject);
    setBody(sample.body);
    setData(null);
    setError(null);
  }

  function clearEml() {
    setEmlContent(null);
    setEmlName(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  function loadEmlFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => {
      setEmlContent(String(reader.result ?? ""));
      setEmlName(file.name);
      setData(null);
      setError(null);
    };
    reader.onerror = () => setError("Could not read the file.");
    reader.readAsText(file);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setTraces({});
    try {
      const payload = emlContent ? { org, eml: emlContent } : { org, sender, subject, body };
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error ?? "Analysis failed");
      }
      const record = await res.json();
      setData(record);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  async function traceLink(url: string) {
    setTraces((t) => ({ ...t, [url]: { state: "loading" } }));
    try {
      const res = await fetch("/api/trace", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error ?? "Trace failed");
      }
      const result = await res.json();
      setTraces((t) => ({ ...t, [url]: { state: "done", ...result } }));
    } catch (err) {
      setTraces((t) => ({
        ...t,
        [url]: { state: "error", message: err instanceof Error ? err.message : "Trace failed" },
      }));
    }
  }

  const auth = data?.headerReport?.authenticationResults;

  return (
    <div className="grid gap-8 lg:grid-cols-2">
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const file = e.dataTransfer.files?.[0];
            if (file) loadEmlFile(file);
          }}
          onClick={() => fileInputRef.current?.click()}
          className={`cursor-pointer border border-dashed p-4 text-center text-sm ${
            dragOver
              ? "border-black bg-black/5 dark:border-white dark:bg-white/10"
              : "border-black/30 text-black/60 dark:border-white/30 dark:text-white/60"
          }`}
        >
          {emlName ? (
            <span>
              Loaded <span className="font-mono">{emlName}</span> — header forensics enabled.{" "}
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  clearEml();
                }}
                className="underline underline-offset-2"
              >
                Remove
              </button>
            </span>
          ) : (
            <>
              <p>
                Drop a raw email (.eml) here for full header analysis, or fill the fields below
                manually.
              </p>
              {/* Clicking anywhere in the zone is a mouse convenience; this button is the
                  keyboard- and screen-reader-reachable path to the same file picker. */}
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  fileInputRef.current?.click();
                }}
                className="mt-2 border border-black/30 px-3 py-1.5 text-xs font-medium hover:bg-black/5 dark:border-white/30 dark:hover:bg-white/10"
              >
                Browse for .eml file
              </button>
            </>
          )}
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml,message/rfc822"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) loadEmlFile(file);
            }}
          />
        </div>

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
            className="border border-black/30 bg-transparent px-3 py-2 focus:border-black dark:border-white/30 dark:focus:border-white"
          />
        </label>

        {!emlContent && (
          <>
            <label className="flex flex-col gap-1.5 text-sm">
              <span className="font-medium">Sender</span>
              <input
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                placeholder="Display Name <address@domain.com>"
                className="border border-black/30 bg-transparent px-3 py-2 focus:border-black dark:border-white/30 dark:focus:border-white"
              />
            </label>

            <label className="flex flex-col gap-1.5 text-sm">
              <span className="font-medium">Subject</span>
              <input
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="Email subject line"
                className="border border-black/30 bg-transparent px-3 py-2 focus:border-black dark:border-white/30 dark:focus:border-white"
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
                className="border border-black/30 bg-transparent px-3 py-2 font-mono text-xs focus:border-black dark:border-white/30 dark:focus:border-white"
              />
            </label>
          </>
        )}

        <button
          type="submit"
          disabled={loading}
          aria-busy={loading}
          className="border border-black bg-black px-4 py-2.5 font-medium text-white hover:bg-black/80 disabled:opacity-50 dark:border-white dark:bg-white dark:text-black dark:hover:bg-white/80"
        >
          {loading ? "Analyzing…" : "Analyze message"}
        </button>
        {error && (
          <p role="alert" className="text-sm text-red-700 dark:text-red-400">
            {error}
          </p>
        )}
      </form>

      <div className="flex flex-col gap-4">
        {!data && (
          <div className="flex h-full min-h-72 flex-col items-center justify-center border border-dashed border-black/30 p-8 text-center text-sm text-black/60 dark:border-white/30 dark:text-white/60">
            Paste a message, load a sample, or drop a .eml file — then click Analyze.
          </div>
        )}

        {data && (
          <>
            <div className="flex flex-col items-center justify-center gap-2 border border-black/30 p-6 dark:border-white/30">
              <RiskGauge score={data.result.score} level={data.result.level} />
              <a
                href={`/report/${data.id}`}
                target="_blank"
                rel="noreferrer"
                className="text-sm underline underline-offset-2"
              >
                View full incident report →
              </a>
            </div>

            {data.aiExplanation && (
              <div className="border border-black/30 p-4 dark:border-white/30">
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide">AI summary</p>
                <p className="whitespace-pre-line text-sm">{data.aiExplanation}</p>
              </div>
            )}

            {(data.aiStatus === "timeout" || data.aiStatus === "error") && (
              <p className="text-xs text-black/60 dark:text-white/60">
                AI summary unavailable ({data.aiStatus === "timeout" ? "request timed out" : "service error"}) —
                showing heuristic results only.
              </p>
            )}

            {data.headerReport && (
              <div className="border border-black/30 dark:border-white/30">
                <p className="border-b border-black/30 px-4 py-3 text-sm font-semibold dark:border-white/30">
                  Header forensics
                </p>
                <div className="grid grid-cols-[110px_1fr] gap-x-4 gap-y-1.5 p-4 text-sm">
                  <span className="font-medium">SPF</span>
                  <span className="font-mono text-xs">{auth?.spf ?? "not present"}</span>
                  <span className="font-medium">DKIM</span>
                  <span className="font-mono text-xs">{auth?.dkim ?? "not present"}</span>
                  <span className="font-medium">DMARC</span>
                  <span className="font-mono text-xs">{auth?.dmarc ?? "not present"}</span>
                  <span className="font-medium">Return-Path</span>
                  <span className="font-mono text-xs">{data.headerReport.returnPathDomain ?? "—"}</span>
                  <span className="font-medium">Reply-To</span>
                  <span className="font-mono text-xs">{data.headerReport.replyToDomain ?? "—"}</span>
                  <span className="font-medium">Delivery hops</span>
                  <span className="font-mono text-xs">{data.headerReport.receivedChain.length}</span>
                </div>
              </div>
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
                    <span className="ml-auto shrink-0 text-xs font-semibold text-black/60 dark:text-white/60">
                      +{ind.weight}
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            {data.result.urls.length > 0 && (
              <div className="border border-black/30 p-4 dark:border-white/30">
                <p className="mb-2 text-sm font-semibold">Extracted links</p>
                <ul className="space-y-3 text-xs">
                  {data.result.urls.map((u) => {
                    const trace = traces[u];
                    return (
                      <li key={u}>
                        <div className="flex items-center gap-3">
                          <span className="break-all font-mono text-black/60 dark:text-white/60">{u}</span>
                          <button
                            type="button"
                            onClick={() => traceLink(u)}
                            disabled={trace?.state === "loading"}
                            className="ml-auto shrink-0 border border-black/30 px-2 py-1 font-medium hover:bg-black/5 disabled:opacity-50 dark:border-white/30 dark:hover:bg-white/10"
                          >
                            {trace?.state === "loading" ? "Tracing…" : "Trace destination"}
                          </button>
                        </div>
                        {trace?.state === "error" && (
                          <p className="mt-1 text-red-700 dark:text-red-400">{trace.message}</p>
                        )}
                        {trace?.state === "done" && (
                          <div className="mt-2 border border-black/15 p-2 dark:border-white/15">
                            <ol className="space-y-0.5 font-mono">
                              {trace.hops.map((hop, i) => (
                                <li key={i} className="break-all">
                                  {i + 1}. {hop.url}{" "}
                                  <span className="text-black/60 dark:text-white/60">
                                    {hop.status !== null ? `[${hop.status}]` : hop.note ? `[${hop.note}]` : ""}
                                  </span>
                                </li>
                              ))}
                            </ol>
                            {trace.blocked && (
                              <p className="mt-1 font-medium text-red-700 dark:text-red-400">
                                Blocked: {trace.blockedReason}
                              </p>
                            )}
                            {!trace.blocked && trace.finalUrl && trace.hops.length > 1 && (
                              <p className="mt-1 text-black/60 dark:text-white/60">
                                Redirects {trace.hops.length - 1}× before landing at{" "}
                                <span className="break-all font-mono">{trace.finalUrl}</span>
                              </p>
                            )}
                            {!trace.blocked && trace.finalUrl && trace.hops.length === 1 && (
                              <p className="mt-1 text-black/60 dark:text-white/60">
                                No redirects — link goes directly to this address.
                              </p>
                            )}
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
