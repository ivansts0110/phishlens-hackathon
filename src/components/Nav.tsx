import Link from "next/link";

export function Nav() {
  return (
    <header className="border-b border-black/10 dark:border-white/10">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
        <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
          <span className="flex h-7 w-7 items-center justify-center rounded-md bg-indigo-600 text-sm text-white">
            PL
          </span>
          <span>PhishLens</span>
        </Link>
        <nav className="flex items-center gap-6 text-sm">
          <Link href="/" className="hover:text-indigo-500">
            Analyzer
          </Link>
          <Link href="/dashboard" className="hover:text-indigo-500">
            Dashboard
          </Link>
        </nav>
      </div>
    </header>
  );
}
