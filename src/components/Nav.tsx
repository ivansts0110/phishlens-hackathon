import Link from "next/link";

export function Nav() {
  return (
    <header className="border-b border-black/20 dark:border-white/20">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-3">
        <Link href="/" className="font-semibold">
          PhishLens
        </Link>
        <nav className="flex items-center gap-4 text-sm">
          <Link href="/" className="underline-offset-2 hover:underline">
            Analyzer
          </Link>
          <Link href="/dashboard" className="underline-offset-2 hover:underline">
            Dashboard
          </Link>
        </nav>
      </div>
    </header>
  );
}
