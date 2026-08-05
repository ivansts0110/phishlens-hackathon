import { test } from "node:test";
import assert from "node:assert/strict";
import { analyze } from "./phishing-engine";

test("benign internal email scores Low with no indicators", () => {
  const result = analyze({
    sender: "Priya Nair <priya.nair@acme-corp.com>",
    subject: "Notes from today's design review",
    body: "Hi team,\n\nSharing notes here: https://acme-corp.com/docs/design-review-notes\n\nBest,\nPriya",
  });
  assert.equal(result.level, "Low");
  assert.equal(result.indicators.length, 0);
});

test("classic brand-impersonation phishing scores Critical", () => {
  const result = analyze({
    sender: "PayPal Security <security@paypa1-support.com>",
    subject: "Your account has been limited - action required",
    body: "Dear Customer,\n\nYour account will be locked within 24 hours. Please verify your password at http://paypa1-support.com/verify",
  });
  assert.equal(result.level, "Critical");
  assert.ok(result.indicators.some((i) => i.id === "impersonation-paypal.com"));
  assert.ok(result.indicators.some((i) => i.id === "urgency"));
  assert.ok(result.indicators.some((i) => i.id === "threat"));
  assert.ok(result.indicators.some((i) => i.id === "credential-harvest"));
});

test("brand name embedded in domain is caught even with no brand mention in display name", () => {
  const result = analyze({
    sender: "Account Team <noreply@paypal-secure-verify.com>",
    subject: "Verify now",
    body: "Please verify your account and confirm your password.",
  });
  assert.ok(result.indicators.some((i) => i.id === "impersonation-paypal.com"));
});

test("mixed-script homograph domain is flagged independent of the brand list", () => {
  const result = analyze({
    sender: "Apple <support@аpple.com>",
    subject: "iCloud verification",
    body: "verify your account",
  });
  assert.ok(result.indicators.some((i) => i.id === "homograph-mixed-script"));
});

test("raw IP-address link is flagged", () => {
  const result = analyze({
    sender: "Notice <alerts@example.com>",
    subject: "Invoice",
    body: "View your invoice: http://192.168.1.50/invoice",
  });
  assert.ok(result.indicators.some((i) => i.id === "ip-url"));
});

test("URL shortener is flagged", () => {
  const result = analyze({
    sender: "Notice <alerts@example.com>",
    subject: "Package update",
    body: "Track your package: http://bit.ly/abcd1234",
  });
  assert.ok(result.indicators.some((i) => i.id === "shortener"));
});

test("mismatched link text vs destination is flagged", () => {
  const result = analyze({
    sender: "DocuSign <no-reply@docusign-verify.top>",
    subject: "Sign now",
    body: "[https://docusign.com/review](http://docusign-verify.top/sign)",
  });
  assert.ok(result.indicators.some((i) => i.id === "link-mismatch"));
});

test("score is capped at 100", () => {
  const result = analyze({
    sender: "PayPal Security <security@paypa1-support.top>",
    subject: "URGENT: account suspended, act now, immediate action required",
    body: `Dear Customer,

Unusual activity detected, unauthorized access, your account will be closed. Failure to comply will result in legal action.

Verify your password, confirm your identity, and confirm your account at http://192.168.1.1/verify or http://bit.ly/xyz. This is your final notice, act now, immediately.

Attachment: invoice.exe`,
  });
  assert.ok(result.score <= 100);
  assert.equal(result.level, "Critical");
});

test("a legitimate brand domain is never flagged as impersonating a similar brand", () => {
  const result = analyze({
    sender: "GitHub <noreply@github.com>",
    subject: "Your weekly digest",
    body: "Here are the repositories you follow this week: https://github.com/explore",
  });
  assert.ok(!result.indicators.some((i) => i.id.startsWith("impersonation-")));
});

test("usps.com is not flagged as impersonating UPS", () => {
  const result = analyze({
    sender: "USPS <tracking@usps.com>",
    subject: "Your package is on the way",
    body: "Track your shipment at https://usps.com/tracking",
  });
  assert.ok(!result.indicators.some((i) => i.id.startsWith("impersonation-")));
});

test("typosquat of a long brand label is still caught", () => {
  const result = analyze({
    sender: "Support <billing@paypal-billing.com>",
    subject: "Invoice",
    body: "See attached.",
  });
  assert.ok(result.indicators.some((i) => i.id === "impersonation-paypal.com"));
});

test("a legitimate non-Latin domain is not flagged as mixed-script", () => {
  const result = analyze({
    sender: "Магазин <info@пример.com>",
    subject: "Заказ подтверждён",
    body: "Спасибо за покупку: https://пример.com/orders",
  });
  assert.ok(!result.indicators.some((i) => i.id === "homograph-mixed-script"));
});

test("a domain label mixing Latin and Cyrillic is still flagged", () => {
  const result = analyze({
    sender: "Apple <support@аpple.com>",
    subject: "Verify your account",
    body: "Sign in at https://аpple.com/verify",
  });
  assert.ok(result.indicators.some((i) => i.id === "homograph-mixed-script"));
});

test("a legitimate IDN domain is not pushed out of the Low band by punycode alone", () => {
  const result = analyze({
    sender: "Информация <info@пример.com>",
    subject: "Новости",
    body: "Подробности на сайте: https://пример.com/news",
  });
  assert.equal(result.level, "Low");
});
