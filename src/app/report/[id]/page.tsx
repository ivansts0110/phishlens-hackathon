import { notFound } from "next/navigation";
import Link from "next/link";
import { getScan } from "@/lib/store";
import { PrintButton } from "@/components/PrintButton";

const LEVEL_TEXT: Record<string, string> = {
  Low: "text-green-700",
  Medium: "text-yellow-700",
  High: "text-orange-700",
  Critical: "text-red-700",
};

export default async function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const scan = getScan(id);
  if (!scan) notFound();

  const auth = scan.headerReport?.authenticationResults;

  return (
    <main id="main" className="mx-auto w-full max-w-3xl px-8 py-10 print:py-4">
      <div className="mb-6 flex items-center justify-between print:hidden">
        <Link href="/" className="text-sm underline-offset-2 hover:underline">
          ← Back to analyzer
        </Link>
        <PrintButton />
      </div>

      <h1 className="text-xl font-bold">PhishLens Incident Report</h1>
      <p className="mb-6 text-sm text-black/60 dark:text-white/60 print:text-black/60">
        Scan {scan.id} — {new Date(scan.createdAt).toLocaleString()}
      </p>

      <section className="mb-6 border border-black/30 dark:border-white/30 print:border-black/30">
        <div className="grid grid-cols-[140px_1fr] gap-x-4 gap-y-2 p-4 text-sm">
          <span className="font-medium">Verdict</span>
          <span className={`font-bold ${LEVEL_TEXT[scan.result.level]}`}>
            {scan.result.level.toUpperCase()} — {scan.result.score}/100
          </span>
          <span className="font-medium">Organization</span>
          <span>{scan.org}</span>
          <span className="font-medium">Sender</span>
          <span className="break-all font-mono text-xs">{scan.sender || "—"}</span>
          <span className="font-medium">Subject</span>
          <span>{scan.subject || "—"}</span>
        </div>
      </section>

      {scan.aiExplanation && (
        <section className="mb-6 border border-black/30 p-4 dark:border-white/30 print:border-black/30">
          <h2 className="mb-1 text-sm font-semibold uppercase tracking-wide">Analyst summary</h2>
          <p className="whitespace-pre-line text-sm">{scan.aiExplanation}</p>
        </section>
      )}

      <section className="mb-6 border border-black/30 dark:border-white/30 print:border-black/30">
        <h2 className="border-b border-black/30 px-4 py-3 text-sm font-semibold dark:border-white/30 print:border-black/30">
          Detected indicators ({scan.result.indicators.length})
        </h2>
        {scan.result.indicators.length === 0 ? (
          <p className="p-4 text-sm text-black/60 dark:text-white/60">No indicators detected.</p>
        ) : (
          <ul className="divide-y divide-black/15 dark:divide-white/15 print:divide-black/15">
            {scan.result.indicators.map((ind) => (
              <li key={ind.id} className="px-4 py-3 text-sm">
                <p className="font-medium">
                  {ind.label} <span className="font-normal text-black/60 dark:text-white/60">(+{ind.weight})</span>
                </p>
                <p className="text-black/60 dark:text-white/60">{ind.detail}</p>
              </li>
            ))}
          </ul>
        )}
      </section>

      {scan.headerReport && (
        <section className="mb-6 border border-black/30 dark:border-white/30 print:border-black/30">
          <h2 className="border-b border-black/30 px-4 py-3 text-sm font-semibold dark:border-white/30 print:border-black/30">
            Email header forensics
          </h2>
          <div className="grid grid-cols-[140px_1fr] gap-x-4 gap-y-2 p-4 text-sm">
            <span className="font-medium">SPF</span>
            <span className="font-mono text-xs">{auth?.spf ?? "not present"}</span>
            <span className="font-medium">DKIM</span>
            <span className="font-mono text-xs">{auth?.dkim ?? "not present"}</span>
            <span className="font-medium">DMARC</span>
            <span className="font-mono text-xs">{auth?.dmarc ?? "not present"}</span>
            <span className="font-medium">From domain</span>
            <span className="font-mono text-xs">{scan.headerReport.fromDomain ?? "—"}</span>
            <span className="font-medium">Return-Path</span>
            <span className="font-mono text-xs">{scan.headerReport.returnPathDomain ?? "—"}</span>
            <span className="font-medium">Reply-To</span>
            <span className="font-mono text-xs">{scan.headerReport.replyToDomain ?? "—"}</span>
          </div>
          {scan.headerReport.receivedChain.length > 0 && (
            <div className="border-t border-black/15 p-4 dark:border-white/15 print:border-black/15">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide">
                Delivery path ({scan.headerReport.receivedChain.length} hops, newest first)
              </p>
              <ol className="space-y-1 font-mono text-xs text-black/60 dark:text-white/60">
                {scan.headerReport.receivedChain.map((hop, i) => (
                  <li key={i} className="break-all">
                    {i + 1}. {hop}
                  </li>
                ))}
              </ol>
            </div>
          )}
        </section>
      )}

      {scan.result.urls.length > 0 && (
        <section className="mb-6 border border-black/30 p-4 dark:border-white/30 print:border-black/30">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide">Links found in message</h2>
          <ul className="space-y-1 font-mono text-xs text-black/60 dark:text-white/60">
            {scan.result.urls.map((u) => (
              <li key={u} className="break-all">
                {u}
              </li>
            ))}
          </ul>
        </section>
      )}

      <p className="text-xs text-black/60 dark:text-white/60">
        Generated by PhishLens. Heuristic analysis is advisory and should be combined with your
        organization&apos;s security procedures. Do not click links or open attachments from messages
        rated Medium or above.
      </p>
    </main>
  );
}
