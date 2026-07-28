"use client";

import { useEffect, useMemo, useState } from "react";
import { Nav } from "@/components/Nav";
import type { ScanRecord } from "@/lib/store";

const LEVEL_ORDER = ["Low", "Medium", "High", "Critical"] as const;

const LEVEL_DOT: Record<string, string> = {
  Low: "bg-emerald-500",
  Medium: "bg-amber-500",
  High: "bg-orange-500",
  Critical: "bg-red-600",
};

const LEVEL_TEXT: Record<string, string> = {
  Low: "text-emerald-600 dark:text-emerald-400",
  Medium: "text-amber-600 dark:text-amber-400",
  High: "text-orange-600 dark:text-orange-400",
  Critical: "text-red-600 dark:text-red-400",
};

export default function Dashboard() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [orgs, setOrgs] = useState<string[]>([]);
  const [org, setOrg] = useState("All");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    fetch(`/api/history?org=${encodeURIComponent(org)}`)
      .then((r) => r.json())
      .then((data) => {
        setScans(data.scans);
        setOrgs(data.orgs);
      })
      .finally(() => setLoading(false));
  }, [org]);

  const stats = useMemo(() => {
    const total = scans.length;
    const avgScore = total ? Math.round(scans.reduce((s, r) => s + r.result.score, 0) / total) : 0;
    const byLevel: Record<string, number> = { Low: 0, Medium: 0, High: 0, Critical: 0 };
    const indicatorCounts = new Map<string, number>();
    for (const s of scans) {
      byLevel[s.result.level] = (byLevel[s.result.level] ?? 0) + 1;
      for (const ind of s.result.indicators) {
        indicatorCounts.set(ind.label, (indicatorCounts.get(ind.label) ?? 0) + 1);
      }
    }
    const topIndicator = Array.from(indicatorCounts.entries()).sort((a, b) => b[1] - a[1])[0];
    return { total, avgScore, byLevel, topIndicator };
  }, [scans]);

  return (
    <div className="flex min-h-full flex-1 flex-col">
      <Nav />
      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-10">
        <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Security dashboard</h1>
            <p className="mt-1 text-sm text-black/60 dark:text-white/60">
              Scan history across your organization&apos;s mailboxes.
            </p>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <span className="font-medium">Organization</span>
            <select
              value={org}
              onChange={(e) => setOrg(e.target.value)}
              className="rounded-lg border border-black/10 bg-transparent px-3 py-1.5 outline-none focus:border-indigo-500 dark:border-white/15"
            >
              <option value="All">All organizations</option>
              {orgs.map((o) => (
                <option key={o} value={o}>
                  {o}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="mb-8 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatTile label="Total scans" value={stats.total.toString()} />
          <StatTile label="Average risk score" value={stats.avgScore.toString()} />
          <StatTile
            label="High + Critical"
            value={((stats.byLevel.High ?? 0) + (stats.byLevel.Critical ?? 0)).toString()}
          />
          <StatTile label="Top indicator" value={stats.topIndicator?.[0] ?? "—"} small />
        </div>

        <div className="mb-8 rounded-xl border border-black/10 p-5 dark:border-white/10">
          <p className="mb-3 text-sm font-semibold">Risk distribution</p>
          <div className="flex h-3 w-full overflow-hidden rounded-full bg-black/5 dark:bg-white/10">
            {LEVEL_ORDER.map((level) => {
              const count = stats.byLevel[level] ?? 0;
              const pct = stats.total ? (count / stats.total) * 100 : 0;
              return pct > 0 ? (
                <div key={level} className={LEVEL_DOT[level]} style={{ width: `${pct}%` }} />
              ) : null;
            })}
          </div>
          <div className="mt-3 flex flex-wrap gap-4 text-xs">
            {LEVEL_ORDER.map((level) => (
              <span key={level} className="flex items-center gap-1.5">
                <span className={`h-2 w-2 rounded-full ${LEVEL_DOT[level]}`} />
                {level} ({stats.byLevel[level] ?? 0})
              </span>
            ))}
          </div>
        </div>

        <div className="overflow-hidden rounded-xl border border-black/10 dark:border-white/10">
          <table className="w-full text-sm">
            <thead className="border-b border-black/10 bg-black/[0.02] text-left text-xs uppercase tracking-wide text-black/50 dark:border-white/10 dark:bg-white/[0.02] dark:text-white/50">
              <tr>
                <th className="px-4 py-3 font-medium">Time</th>
                <th className="px-4 py-3 font-medium">Organization</th>
                <th className="px-4 py-3 font-medium">Sender</th>
                <th className="px-4 py-3 font-medium">Subject</th>
                <th className="px-4 py-3 font-medium text-right">Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-black/5 dark:divide-white/5">
              {loading && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-black/50 dark:text-white/50">
                    Loading…
                  </td>
                </tr>
              )}
              {!loading && scans.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-black/50 dark:text-white/50">
                    No scans yet.
                  </td>
                </tr>
              )}
              {scans.map((s) => (
                <tr key={s.id}>
                  <td className="whitespace-nowrap px-4 py-3 text-black/60 dark:text-white/60">
                    {new Date(s.createdAt).toLocaleString(undefined, {
                      month: "short",
                      day: "numeric",
                      hour: "numeric",
                      minute: "2-digit",
                    })}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3">{s.org}</td>
                  <td className="max-w-[220px] truncate px-4 py-3 font-mono text-xs">{s.sender || "—"}</td>
                  <td className="max-w-[260px] truncate px-4 py-3">{s.subject || "—"}</td>
                  <td className={`px-4 py-3 text-right font-semibold ${LEVEL_TEXT[s.result.level]}`}>
                    {s.result.score}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}

function StatTile({ label, value, small }: { label: string; value: string; small?: boolean }) {
  return (
    <div className="rounded-xl border border-black/10 p-4 dark:border-white/10">
      <p className="text-xs font-medium uppercase tracking-wide text-black/50 dark:text-white/50">{label}</p>
      <p className={`mt-1.5 font-semibold ${small ? "truncate text-sm" : "text-2xl"}`}>{value}</p>
    </div>
  );
}
