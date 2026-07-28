"use client";

export function PrintButton() {
  return (
    <button
      type="button"
      onClick={() => window.print()}
      className="border border-black/30 px-3 py-1.5 text-sm font-medium hover:bg-black/5 dark:border-white/30 dark:hover:bg-white/10"
    >
      Print / save as PDF
    </button>
  );
}
