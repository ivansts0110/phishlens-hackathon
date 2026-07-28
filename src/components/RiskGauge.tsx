const LEVEL_STYLES: Record<string, { ring: string; text: string; bg: string }> = {
  Low: { ring: "stroke-emerald-500", text: "text-emerald-600 dark:text-emerald-400", bg: "bg-emerald-500/10" },
  Medium: { ring: "stroke-amber-500", text: "text-amber-600 dark:text-amber-400", bg: "bg-amber-500/10" },
  High: { ring: "stroke-orange-500", text: "text-orange-600 dark:text-orange-400", bg: "bg-orange-500/10" },
  Critical: { ring: "stroke-red-600", text: "text-red-600 dark:text-red-400", bg: "bg-red-500/10" },
};

export function RiskGauge({ score, level }: { score: number; level: string }) {
  const style = LEVEL_STYLES[level] ?? LEVEL_STYLES.Low;
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative h-36 w-36">
        <svg className="h-full w-full -rotate-90" viewBox="0 0 128 128">
          <circle cx="64" cy="64" r={radius} strokeWidth="10" fill="none" className="stroke-black/10 dark:stroke-white/10" />
          <circle
            cx="64"
            cy="64"
            r={radius}
            strokeWidth="10"
            fill="none"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className={`${style.ring} transition-[stroke-dashoffset] duration-500 ease-out`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold">{score}</span>
          <span className="text-xs text-black/50 dark:text-white/50">/ 100</span>
        </div>
      </div>
      <span className={`rounded-full px-3 py-1 text-sm font-medium ${style.bg} ${style.text}`}>
        {level} risk
      </span>
    </div>
  );
}
