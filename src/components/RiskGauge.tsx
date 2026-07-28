const LEVEL_TEXT: Record<string, string> = {
  Low: "text-green-700 dark:text-green-400",
  Medium: "text-yellow-700 dark:text-yellow-400",
  High: "text-orange-700 dark:text-orange-400",
  Critical: "text-red-700 dark:text-red-400",
};

export function RiskGauge({ score, level }: { score: number; level: string }) {
  const color = LEVEL_TEXT[level] ?? LEVEL_TEXT.Low;

  return (
    <div className="flex flex-col items-center gap-1">
      <span className={`text-4xl font-bold ${color}`}>
        {score}
        <span className="text-lg font-normal text-black/60 dark:text-white/60"> / 100</span>
      </span>
      <span className={`text-sm font-medium uppercase tracking-wide ${color}`}>{level} risk</span>
    </div>
  );
}
