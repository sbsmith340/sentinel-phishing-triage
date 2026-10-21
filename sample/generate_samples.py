"""
Generate a labeled, fully synthetic set of reported emails for testing the scorer.

All domains are fictional (contoso.com is the "protected" org) or reserved
examples. No real mail, users, or tenants are used.

Usage:  python sample/generate_samples.py --count 200 --seed 7
Output: sample/reported_emails.jsonl   (one JSON object per line, with "label")
"""
import argparse
import json
import random
from pathlib import Path

ORG = "contoso.com"
COLLEAGUES = ["jordan.lee", "priya.patel", "marcus.green", "ana.ruiz", "kevin.ng"]
VENDORS = ["fabrikam.com", "northwindtraders.com", "adventure-works.com", "litware.com"]
NEWSLETTERS = ["news.tailspintoys.com", "updates.wingtiptoys.com", "mail.proseware.com"]

LOOKALIKES = ["c0ntoso.com", "contosso.com", "contoso-support.com", "contoso.com.secure-login.net",
              "conteso.com", "rnicrosoft-contoso.com"]
BAD_HOSTS = ["login-verify.example.net", "secure-docs.example.org", "203.0.113.45", "198.51.100.7"]
SHORT = ["bit.ly/3xYz", "tinyurl.com/acct-check", "cutt.ly/inv88"]

BENIGN_SUBJECTS = ["Q4 planning notes", "Lunch Thursday?", "Updated timesheet policy",
                   "Your monthly newsletter", "Invoice #{n} attached", "Meeting moved to 3pm",
                   "Weekly product digest", "Re: project status"]
PHISH_SUBJECTS = ["Action required: verify your account", "Unusual sign-in activity detected",
                  "Your mailbox is full - final notice", "Payroll update: confirm your credentials",
                  "URGENT: invoice overdue, pay immediately", "Shared document: sign in to view",
                  "Password expires within 24 hours"]


def benign(rng, i):
    kind = rng.choice(["internal", "vendor", "newsletter"])
    if kind == "internal":
        user = rng.choice(COLLEAGUES)
        sender, name, links, att = f"{user}@{ORG}", user.replace(".", " ").title(), [], []
        if rng.random() < 0.3:
            links = [{"url": f"https://sharepoint.{ORG}/sites/team/doc{i}", "display_text": "the doc"}]
        if rng.random() < 0.2:
            att = [rng.choice(["notes.docx", "budget.xlsx", "slides.pptx"])]
        first = False
    elif kind == "vendor":
        dom = rng.choice(VENDORS)
        sender, name = f"billing@{dom}", dom.split(".")[0].title() + " Billing"
        links = [{"url": f"https://portal.{dom}/invoices/{i}", "display_text": f"portal.{dom}"}]
        att = ["invoice.pdf"] if rng.random() < 0.6 else []
        first = rng.random() < 0.2
    else:
        dom = rng.choice(NEWSLETTERS)
        sender, name = f"no-reply@{dom}", dom.split(".")[1].title()
        links = [{"url": f"https://{dom}/read/{i}", "display_text": "Read more"}]
        att, first = [], rng.random() < 0.3
    return {
        "sender_address": sender, "sender_display_name": name,
        "reply_to": "", "subject": rng.choice(BENIGN_SUBJECTS).format(n=1000 + i),
        "body": "Hi team, see details below. Thanks.",
        "links": links, "attachments": att,
        "spf": "pass", "dkim": "pass", "dmarc": "pass" if rng.random() > 0.05 else "none",
        "first_time_sender": first, "label": "phish" if False else "benign",
    }


def phish(rng, i):
    style = rng.choice(["lookalike", "spoofed_name", "link_mismatch", "attachment", "shortener"])
    dom = rng.choice(LOOKALIKES) if style == "lookalike" else rng.choice(["example.net", "example.org", "mailer.example.com"])
    sender = f"{rng.choice(['it-support', 'helpdesk', 'payroll', 'security', 'admin'])}@{dom}"
    name = rng.choice(["Contoso IT", "Contoso Payroll", "IT Helpdesk", "Microsoft 365 Team", "Security Team"])
    if style == "spoofed_name":
        name = "Contoso IT Support"
    bad = rng.choice(BAD_HOSTS)
    links = [{"url": f"http://{bad}/login?id={i}", "display_text": "Sign in"}]
    if style == "link_mismatch":
        links = [{"url": f"http://{bad}/o365", "display_text": f"https://login.{ORG}"}]
    if style == "shortener":
        links = [{"url": "https://" + rng.choice(SHORT), "display_text": "Review document"}]
    att = []
    if style == "attachment":
        att = [rng.choice(["Invoice_Q4.pdf.html", "remittance.docm", "scan_0042.iso", "payroll.xlsm", "statement.lnk"])]
        links = []
    auth_fail = rng.random() < 0.6
    return {
        "sender_address": sender, "sender_display_name": name,
        "reply_to": f"collect@{rng.choice(['example.com', 'example.net'])}" if rng.random() < 0.4 else "",
        "subject": rng.choice(PHISH_SUBJECTS),
        "body": "Please act immediately to avoid your account being suspended.",
        "links": links, "attachments": att,
        "spf": "fail" if auth_fail else "pass",
        "dkim": "fail" if auth_fail and rng.random() < 0.5 else "pass",
        "dmarc": "fail" if auth_fail else rng.choice(["pass", "none"]),
        "first_time_sender": True, "label": "phish",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=200)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--phish-ratio", type=float, default=0.35)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    out = Path(__file__).with_name("reported_emails.jsonl")
    with out.open("w") as f:
        for i in range(args.count):
            rec = phish(rng, i) if rng.random() < args.phish_ratio else benign(rng, i)
            f.write(json.dumps(rec) + "\n")
    print(f"wrote {args.count} records -> {out}")


if __name__ == "__main__":
    main()
