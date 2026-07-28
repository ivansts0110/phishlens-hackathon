import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishLens — Phishing & Social Engineering Detector",
  description: "Real-time phishing and social-engineering risk analysis for emails and messages.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full">
      <body className="min-h-full flex flex-col font-sans">
        <a href="#main" className="skip-link">
          Skip to main content
        </a>
        {children}
      </body>
    </html>
  );
}
