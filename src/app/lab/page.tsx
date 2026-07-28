"use client";

import { useState } from "react";
import { Nav } from "@/components/Nav";
import { SAMPLES } from "@/lib/samples";

type AttackStep = {
  operator: string;
  technique: string;
  scoreBefore: number;
  scoreAfter: number;
  defeatedIndicators: string[];
  hardenable: boolean;
  recommendation: string;
};

type AttackReport = {
  startScore: number;
  startLevel: string;
  finalScore: number;
  finalLevel: string;
  steps: AttackStep[];
  hardenedFinalScore: number;
  hardenedFinalLevel: string;
  neutralizedByHardening: string[];
  survivingTechniques: string[];
};

const phishSample = SAMPLES.find((s) => s.key === "paypal")!;

function scoreColor(score: number): string {
  if (score >= 75) return "text-red-700 dark:text-red-400";
  if (score >= 50) return "text-orange-700 dark:text-orange-400";
  if (score >= 25) return "text-yellow-700 dark:text-yellow-400";
  return "text-green-700 dark:text-green-400";
}

export default function Lab() {
  const [sender, setSender] = useState(phishSample.sender);
  const [subject, setSubject] = useState(phishSample.subject);
  const [body, setBody] = useState(phishSample.body);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<AttackReport | null>(null);

  async function run() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/redteam", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sender, subject, body }),
      });
      if (!res.ok) throw new Error((await res.json()).error ?? "Red-team run failed");
      setReport(await res.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-full flex-1 flex-col">
      <Nav />
      <main id="main" className="mx-auto w-full max-w-5xl flex-1 px-6 py-10">
        <div className="mb-6">
          <h1 className="text-2xl font-semibold tracking-tight">Adversarial Red-Team Lab</h1>
          <p className="mt-1 max-w-2xl text-sm text-black/60 dark:text-white/60">
            PhishLens attacks its own detector. Give it a message you&apos;ve flagged as phishing and it
            plays the adversary — applying one evasion technique at a time to drive the risk score down,
            exposing which heuristics are brittle and turning every successful evasion into a concrete
            hardening recommendation. A detector that hasn&apos;t been red-teamed is a detector you
            don&apos;t understand.
          </p>
        </div>

        <div className="grid gap-8 lg:grid-cols-2">
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap gap-2">
              {SAMPLES.map((s) => (
                <button
                  key={s.key}
                  type="button"
                  onClick={() => {
                    setSender(s.sender);
                    setSubject(s.subject);
                    setBody(s.body);
                    setReport(null);
                  }}
                  className="border border-black/30 px-3 py-1.5 text-xs font-medium hover:bg-black/5 dark:border-white/30 dark:hover:bg-white/10"
                >
                  {s.label}
                </button>
              ))}
            </div>
            <label className="flex flex-col gap-1.5 text-sm">
              <span className="font-medium">Sender</span>
              <input
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                className="border border-black/30 bg-transparent px-3 py-2 focus:border-black dark:border-white/30 dark:focus:border-white"
              />
            </label>
            <label className="flex flex-col gap-1.5 text-sm">
              <span className="font-medium">Subject</span>
              <input
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                className="border border-black/30 bg-transparent px-3 py-2 focus:border-black dark:border-white/30 dark:focus:border-white"
              />
            </label>
            <label className="flex flex-col gap-1.5 text-sm">
              <span className="font-medium">Message body</span>
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                rows={12}
                className="border border-black/30 bg-transparent px-3 py-2 font-mono text-xs focus:border-black dark:border-white/30 dark:focus:border-white"
              />
            </label>
            <button
              type="button"
              onClick={run}
              disabled={loading}
              aria-busy={loading}
              className="border border-black bg-black px-4 py-2.5 font-medium text-white hover:bg-black/80 disabled:opacity-50 dark:border-white dark:bg-white dark:text-black dark:hover:bg-white/80"
            >
              {loading ? "Running attack…" : "Run adversarial red-team"}
            </button>
            {error && (
              <p role="alert" className="text-sm text-red-700 dark:text-red-400">
                {error}
              </p>
            )}
          </div>

          <div className="flex flex-col gap-4">
            {!report && (
              <div className="flex h-full min-h-72 items-center justify-center border border-dashed border-black/30 p-8 text-center text-sm text-black/60 dark:border-white/30 dark:text-white/60">
                Run the red-team to watch the detector get evaded step by step.
              </div>
            )}

            {report && (
              <>
                <div className="flex items-center justify-around border border-black/30 p-4 text-center dark:border-white/30">
                  <div>
                    <p className="text-xs uppercase tracking-wide text-black/60 dark:text-white/60">Start</p>
                    <p className={`text-3xl font-bold ${scoreColor(report.startScore)}`}>{report.startScore}</p>
                    <p className="text-xs">{report.startLevel}</p>
                  </div>
                  <div className="text-2xl text-black/30 dark:text-white/30">→</div>
                  <div>
                    <p className="text-xs uppercase tracking-wide text-black/60 dark:text-white/60">Evaded</p>
                    <p className={`text-3xl font-bold ${scoreColor(report.finalScore)}`}>{report.finalScore}</p>
                    <p className="text-xs">{report.finalLevel}</p>
                  </div>
                </div>

                <ol className="flex flex-col gap-3">
                  {report.steps.map((step, i) => (
                    <li key={i} className="border border-black/30 dark:border-white/30">
                      <div className="flex items-center justify-between border-b border-black/15 px-4 py-2 dark:border-white/15">
                        <span className="text-sm font-semibold">
                          {i + 1}. {step.operator}
                        </span>
                        <span className="font-mono text-xs">
                          <span className={scoreColor(step.scoreBefore)}>{step.scoreBefore}</span>
                          <span className="text-black/60 dark:text-white/60"> → </span>
                          <span className={scoreColor(step.scoreAfter)}>{step.scoreAfter}</span>
                        </span>
                      </div>
                      <div className="px-4 py-3 text-sm">
                        <p className="text-black/70 dark:text-white/70">{step.technique}</p>
                        {step.defeatedIndicators.length > 0 && (
                          <p className="mt-2 text-xs">
                            <span className="font-medium">Defeated:</span>{" "}
                            {step.defeatedIndicators.join(", ")}
                          </p>
                        )}
                        <p className="mt-2 border-l-2 border-black/30 pl-2 text-xs text-black/60 dark:border-white/30 dark:text-white/60">
                          <span className="font-medium">
                            {step.hardenable ? "Hardening (applied): " : "Requires deeper layer: "}
                          </span>
                          {step.recommendation}
                        </p>
                      </div>
                    </li>
                  ))}
                </ol>

                <div className="border border-black/30 p-4 dark:border-white/30">
                  <p className="mb-2 text-sm font-semibold">Hardening report</p>
                  <p className="text-sm text-black/70 dark:text-white/70">
                    Against a naive keyword filter, this message was driven from{" "}
                    <span className="font-semibold">{report.startScore}</span> to{" "}
                    <span className="font-semibold">{report.finalScore}</span> in {report.steps.length} step
                    {report.steps.length === 1 ? "" : "s"}.
                  </p>
                  {report.neutralizedByHardening.length > 0 && (
                    <p className="mt-2 text-sm text-black/70 dark:text-white/70">
                      PhishLens&apos;s Unicode-normalization hardening re-detects{" "}
                      <span className="font-semibold">{report.neutralizedByHardening.join(", ")}</span> despite
                      the invisible-character evasion — the same message scores{" "}
                      <span className={`font-semibold ${scoreColor(report.hardenedFinalScore)}`}>
                        {report.hardenedFinalScore}
                      </span>{" "}
                      against the hardened detector, not {report.finalScore}.
                    </p>
                  )}
                  {report.survivingTechniques.length > 0 && (
                    <p className="mt-2 text-sm text-black/70 dark:text-white/70">
                      The remaining evasions ({report.survivingTechniques.join(", ")}) are fundamental limits
                      of content-only analysis — which is exactly why PhishLens also inspects email headers
                      (SPF/DKIM/DMARC), traces link destinations, and consults domain intelligence.
                    </p>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
