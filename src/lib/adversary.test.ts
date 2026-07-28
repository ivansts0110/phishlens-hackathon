import { test } from "node:test";
import assert from "node:assert/strict";
import { redTeam } from "./adversary";
import { analyze } from "./phishing-engine";

const PHISH = {
  sender: "PayPal Security <security@paypa1-support.com>",
  subject: "Your account has been limited - action required",
  body:
    "Dear Customer,\n\nYour account will be locked within 24 hours. Please verify your password " +
    "at http://bit.ly/pp-verify to confirm your account immediately.",
};

test("red-team drives the score down from the starting verdict", () => {
  const report = redTeam(PHISH);
  assert.ok(report.startScore >= 75, "starts Critical");
  assert.ok(report.finalScore < report.startScore, "final score is lower than start");
  assert.ok(report.steps.length > 0, "at least one evasion step");
});

test("each step strictly reduces the score", () => {
  const report = redTeam(PHISH);
  for (const step of report.steps) {
    assert.ok(step.scoreAfter < step.scoreBefore, `${step.operator} reduced score`);
  }
});

test("invisible-character evasion is neutralized by the hardened detector", () => {
  const report = redTeam(PHISH);

  assert.ok(
    report.hardenedFinalScore >= report.finalScore,
    "hardened detector recovers at least as much signal",
  );
  assert.ok(report.neutralizedByHardening.length > 0, "hardening restores at least one indicator");
});

test("hardened analysis strips zero-width injection", () => {
  const obfuscated = "Please verify your p" + "\u200b" + "assword now.";
  const naive = analyze({ sender: "", subject: "", body: obfuscated }, { hardened: false });
  const hardened = analyze({ sender: "", subject: "", body: obfuscated }, { hardened: true });
  assert.ok(!naive.indicators.some((i) => i.id === "credential-harvest"), "naive misses obfuscated phrase");
  assert.ok(hardened.indicators.some((i) => i.id === "credential-harvest"), "hardened catches it");
});
