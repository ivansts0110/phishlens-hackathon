import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeHeaders, type RawHeader } from "./header-analysis";

function h(pairs: [string, string][]): RawHeader[] {
  return pairs.map(([key, value]) => ({ key, value }));
}

test("failing SPF/DKIM/DMARC each produce an indicator", () => {
  const { indicators, report } = analyzeHeaders(
    h([
      [
        "Authentication-Results",
        "mx.acme-corp.com; spf=fail smtp.mailfrom=x.top; dkim=fail header.d=y.top; dmarc=fail (p=none) header.from=y.top",
      ],
      ["From", "PayPal <security@paypa1-support.com>"],
    ]),
  );
  assert.ok(indicators.some((i) => i.id === "header-spf-fail"));
  assert.ok(indicators.some((i) => i.id === "header-dkim-fail"));
  assert.ok(indicators.some((i) => i.id === "header-dmarc-fail"));
  assert.equal(report.authenticationResults.spf, "fail");
});

test("passing authentication produces no auth indicators", () => {
  const { indicators } = analyzeHeaders(
    h([
      ["Authentication-Results", "mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass"],
      ["From", "Priya <priya@acme-corp.com>"],
      ["Return-Path", "<priya@acme-corp.com>"],
    ]),
  );
  assert.equal(indicators.length, 0);
});

test("Return-Path domain mismatch is flagged", () => {
  const { indicators, report } = analyzeHeaders(
    h([
      ["From", "PayPal <security@paypal.com>"],
      ["Return-Path", "<bounce@sketchy-host.top>"],
    ]),
  );
  assert.ok(indicators.some((i) => i.id === "header-return-path-mismatch"));
  assert.equal(report.fromDomain, "paypal.com");
  assert.equal(report.returnPathDomain, "sketchy-host.top");
});

test("Reply-To domain mismatch is flagged", () => {
  const { indicators } = analyzeHeaders(
    h([
      ["From", "CEO <ceo@acme-corp.com>"],
      ["Reply-To", "<attacker@gmail-secure.top>"],
    ]),
  );
  assert.ok(indicators.some((i) => i.id === "header-reply-to-mismatch"));
});

test("received chain is collected", () => {
  const { report } = analyzeHeaders(
    h([
      ["Received", "from a.example.com by mx.acme-corp.com; Tue, 28 Jul 2026 09:14:22 -0700"],
      ["Received", "from b.example.com by a.example.com; Tue, 28 Jul 2026 09:14:20 -0700"],
      ["From", "x@example.com"],
    ]),
  );
  assert.equal(report.receivedChain.length, 2);
});
