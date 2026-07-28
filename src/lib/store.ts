import fs from "node:fs";
import path from "node:path";
import type { AnalysisResult } from "./phishing-engine";

export type ScanRecord = {
  id: string;
  org: string;
  sender: string;
  subject: string;
  createdAt: string;
  result: AnalysisResult;
  aiExplanation?: string;
};

const DATA_DIR = path.join(process.cwd(), "data");
const DATA_FILE = path.join(DATA_DIR, "scans.json");

function ensureStore(): void {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify(seedData(), null, 2));
}

function seedData(): ScanRecord[] {
  const now = Date.now();
  const day = 24 * 60 * 60 * 1000;
  return [
    {
      id: "seed-1",
      org: "Acme Corp",
      sender: "IT Support <helpdesk@acme-corp.com>",
      subject: "Scheduled password rotation reminder",
      createdAt: new Date(now - 6 * day).toISOString(),
      result: { score: 6, level: "Low", indicators: [], urls: [] },
    },
    {
      id: "seed-2",
      org: "Acme Corp",
      sender: "PayPal Security <security@paypa1-support.com>",
      subject: "Your account has been limited - action required",
      createdAt: new Date(now - 5 * day).toISOString(),
      result: {
        score: 82,
        level: "Critical",
        indicators: [
          { id: "impersonation-paypal.com", category: "sender", label: "Likely impersonation of PayPal", detail: "", weight: 35 },
          { id: "threat", category: "urgency", label: "Threatening consequences", detail: "", weight: 15 },
          { id: "credential-harvest", category: "content", label: "Requests credentials or payment info", detail: "", weight: 20 },
        ],
        urls: ["http://paypa1-support.com/verify"],
      },
    },
    {
      id: "seed-3",
      org: "Northwind Health",
      sender: "Payroll <payroll@northwind-health.com>",
      subject: "Q3 benefits enrollment is open",
      createdAt: new Date(now - 4 * day).toISOString(),
      result: { score: 4, level: "Low", indicators: [], urls: [] },
    },
    {
      id: "seed-4",
      org: "Northwind Health",
      sender: "DocuSign <no-reply@docusign-verify.top>",
      subject: "URGENT: Document expires in 24 hours",
      createdAt: new Date(now - 3 * day).toISOString(),
      result: {
        score: 65,
        level: "High",
        indicators: [
          { id: "impersonation-docusign.com", category: "sender", label: "Likely impersonation of DocuSign", detail: "", weight: 22 },
          { id: "urgency", category: "urgency", label: "Urgency / pressure language", detail: "", weight: 20 },
          { id: "suspicious-tld", category: "links", label: "Uncommon top-level domain", detail: "", weight: 15 },
        ],
        urls: ["http://docusign-verify.top/sign"],
      },
    },
    {
      id: "seed-5",
      org: "Acme Corp",
      sender: "Slack <notifications@slack.com>",
      subject: "New message in #general",
      createdAt: new Date(now - 1 * day).toISOString(),
      result: { score: 0, level: "Low", indicators: [], urls: [] },
    },
  ];
}

export function addScan(record: Omit<ScanRecord, "id" | "createdAt">): ScanRecord {
  ensureStore();
  const all: ScanRecord[] = JSON.parse(fs.readFileSync(DATA_FILE, "utf-8"));
  const full: ScanRecord = {
    ...record,
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    createdAt: new Date().toISOString(),
  };
  all.unshift(full);
  fs.writeFileSync(DATA_FILE, JSON.stringify(all.slice(0, 500), null, 2));
  return full;
}

export function listScans(org?: string): ScanRecord[] {
  ensureStore();
  const all: ScanRecord[] = JSON.parse(fs.readFileSync(DATA_FILE, "utf-8"));
  return org && org !== "All" ? all.filter((s) => s.org === org) : all;
}

export function listOrgs(): string[] {
  ensureStore();
  const all: ScanRecord[] = JSON.parse(fs.readFileSync(DATA_FILE, "utf-8"));
  return Array.from(new Set(all.map((s) => s.org))).sort();
}
