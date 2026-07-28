export type Sample = {
  key: string;
  label: string;
  org: string;
  sender: string;
  subject: string;
  body: string;
};

export const SAMPLES: Sample[] = [
  {
    key: "paypal",
    label: "Fake PayPal account alert",
    org: "Acme Corp",
    sender: "PayPal Security <security@paypa1-support.com>",
    subject: "Your account has been limited - action required",
    body: `Dear Customer,

We have detected unusual activity on your PayPal account. Your account will be locked within 24 hours unless you verify your identity immediately.

Please confirm your account by clicking the link below and verifying your password and billing details:

http://paypa1-support.com/verify?id=8842

Failure to comply will result in permanent suspension of your account.

Thank you,
PayPal Security Team`,
  },
  {
    key: "docusign",
    label: "DocuSign urgent signature request",
    org: "Northwind Health",
    sender: "DocuSign <no-reply@docusign-verify.top>",
    subject: "URGENT: Document expires in 24 hours",
    body: `Dear User,

A document has been sent to you for electronic signature via DocuSign. This request will expire in 24 hours.

[https://docusign.com/review](http://docusign-verify.top/sign?ref=99213)

Please review and sign as soon as possible to avoid delays.

Reply-To: support@docusign-notice.top

DocuSign Notifications`,
  },
  {
    key: "safe",
    label: "Legitimate internal email",
    org: "Acme Corp",
    sender: "Priya Nair <priya.nair@acme-corp.com>",
    subject: "Notes from today's design review",
    body: `Hi team,

Thanks for joining today's design review. Sharing the notes doc here: https://acme-corp.com/docs/design-review-notes

Let me know if I missed anything before Thursday's follow-up.

Best,
Priya`,
  },
];
