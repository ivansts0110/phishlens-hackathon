"use client";

import { useEffect, useMemo, useState } from "react";
import { Nav } from "@/components/Nav";
import type { ScanRecord } from "@/lib/store";

const LEVEL_ORDER = ["Low", "Medium", "High", "Critical"] as const;

const LEVEL_COLOR: Record<string, string> = {
  Low: "bg-green-600",
  Medium: "bg-yellow-600",
  High: "bg-orange-600",
  Critical: "bg-red-700",
};

const LEVEL_TEXT: Record<string, string> = {
  Low: "text-green-700 dark:text-green-400",
  Medium: "text-yellow-700 dark:text-yellow-400",
  High: "text-orange-700 dark:text-orange-400",
  Critical: "text-red-700 dark:text-red-400",
};

export default function Dashboard() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [orgs, setOrgs] = useState<string[]>([]);
  const [org, setOrg] = useState("All");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      try {
        const res = await fetch(`/api/history?org=${encodeURIComponent(org)}`);
        const data = await res.json();
        if (cancelled) return;
        setScans(data.scans);
        setOrgs(data.orgs);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();

    return () => {
      cancelled = true;
    };
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
      <main id="main" className="mx-auto w-full max-w-5xl flex-1 px-6 py-10">
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
              className="border border-black/30 bg-transparent px-3 py-1.5 focus:border-black dark:border-white/30 dark:focus:border-white"
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

        <div className="mb-8 border border-black/30 p-5 dark:border-white/30">
          <p className="mb-3 text-sm font-semibold">Risk distribution</p>
          <div className="flex h-3 w-full overflow-hidden border border-black/30 dark:border-white/30">
            {LEVEL_ORDER.map((level) => {
              const count = stats.byLevel[level] ?? 0;
              const pct = stats.total ? (count / stats.total) * 100 : 0;
              return pct > 0 ? (
                <div key={level} className={LEVEL_COLOR[level]} style={{ width: `${pct}%` }} />
              ) : null;
            })}
          </div>
          <div className="mt-3 flex flex-wrap gap-4 text-xs">
            {LEVEL_ORDER.map((level) => (
              <span key={level} className="flex items-center gap-1.5">
                <span className={`h-2 w-2 ${LEVEL_COLOR[level]}`} />
                {level} ({stats.byLevel[level] ?? 0})
              </span>
            ))}
          </div>
        </div>

        <div className="overflow-hidden border border-black/30 dark:border-white/30">
          <table className="w-full text-sm">
            <thead className="border-b border-black/30 text-left text-xs uppercase tracking-wide text-black/60 dark:border-white/30 dark:text-white/60">
              <tr>
                <th scope="col" className="px-4 py-3 font-medium">Time</th>
                <th scope="col" className="px-4 py-3 font-medium">Organization</th>
                <th scope="col" className="px-4 py-3 font-medium">Sender</th>
                <th scope="col" className="px-4 py-3 font-medium">Subject</th>
                <th scope="col" className="px-4 py-3 font-medium text-right">Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-black/15 dark:divide-white/15">
              {loading && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-black/60 dark:text-white/60">
                    Loading…
                  </td>
                </tr>
              )}
              {!loading && scans.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-black/60 dark:text-white/60">
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
    <div className="border border-black/30 p-4 dark:border-white/30">
      <p className="text-xs font-medium uppercase tracking-wide text-black/60 dark:text-white/60">{label}</p>
      <p className={`mt-1.5 font-semibold ${small ? "truncate text-sm" : "text-2xl"}`}>{value}</p>
    </div>
  );
}
