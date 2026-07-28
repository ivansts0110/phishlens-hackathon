import { NextRequest, NextResponse } from "next/server";
import { listScans, listOrgs } from "@/lib/store";

export async function GET(req: NextRequest) {
  const org = req.nextUrl.searchParams.get("org") ?? undefined;
  const scans = listScans(org);
  const orgs = listOrgs();
  return NextResponse.json({ scans, orgs });
}
