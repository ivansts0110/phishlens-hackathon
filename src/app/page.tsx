import { Nav } from "@/components/Nav";
import { AnalyzerForm } from "@/components/AnalyzerForm";

export default function Home() {
  return (
    <div className="flex min-h-full flex-1 flex-col">
      <Nav />
      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-10">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Message analyzer</h1>
          <p className="mt-1 text-sm text-black/60 dark:text-white/60">
            Paste a suspicious email or message. PhishLens scores it against phishing and
            social-engineering indicators in real time, with an optional AI-generated summary.
          </p>
        </div>
        <AnalyzerForm />
      </main>
    </div>
  );
}
