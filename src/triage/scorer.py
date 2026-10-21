"""
Phishing triage scorer.

Takes a normalized email record (see `Email` below) and returns a risk score,
a verdict, and the list of signals that fired, so an analyst can see *why*.

Design goals
- Explainable: every point added is tied to a named signal.
- Deterministic: same input -> same output; easy to unit test.
- No external calls: enrichment (VirusTotal, URLScan, etc.) is optional and
  injected by the caller, so the core logic runs offline and in CI.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Tunables. Kept in one place so tuning decisions are visible in code review.
# --------------------------------------------------------------------------
WEIGHTS = {
    "spf_fail": 15,
    "dkim_fail": 10,
    "dmarc_fail": 20,
    "reply_to_mismatch": 15,
    "display_name_spoof": 25,
    "lookalike_domain": 30,
    "link_text_mismatch": 25,
    "raw_ip_url": 20,
    "url_shortener": 10,
    "risky_attachment": 30,
    "macro_attachment": 25,
    "credential_lure": 15,
    "urgency_language": 10,
    "first_time_sender": 5,
    "known_bad_url": 60,  # only fires when the caller supplies enrichment
}

MALICIOUS_THRESHOLD = 60   # >= this: escalate as likely phish
SUSPICIOUS_THRESHOLD = 30  # >= this: needs analyst review; below: auto-close benign

RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".hta", ".iso", ".img",
                    ".lnk", ".bat", ".cmd", ".ps1", ".html", ".htm", ".svg"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".xlam"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly"}

CREDENTIAL_PATTERNS = re.compile(
    r"\b(verify your (account|identity|password)|reset your password|"
    r"confirm your (credentials|login|account)|sign[- ]in to (review|view)|"
    r"mailbox (is )?(full|suspended)|unusual sign[- ]in)\b", re.I)
URGENCY_PATTERNS = re.compile(
    r"\b(urgent|immediately|within 24 hours|action required|final notice|"
    r"account (will be )?(suspended|locked|closed)|asap)\b", re.I)


@dataclass
class Link:
    url: str
    display_text: str = ""


@dataclass
class Email:
    sender_address: str
    sender_display_name: str = ""
    reply_to: str = ""
    subject: str = ""
    body: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    spf: str = "pass"     # pass | fail | softfail | none
    dkim: str = "pass"    # pass | fail | none
    dmarc: str = "pass"   # pass | fail | none
    first_time_sender: bool = False


@dataclass
class Result:
    score: int
    verdict: str          # "malicious" | "suspicious" | "benign"
    signals: list[str]

    def as_dict(self) -> dict:
        return {"score": self.score, "verdict": self.verdict, "signals": self.signals}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _domain(address_or_url: str) -> str:
    s = address_or_url.strip().lower()
    if "@" in s and "://" not in s:
        return s.rsplit("@", 1)[-1]
    host = urlparse(s if "://" in s else "http://" + s).hostname or ""
    return host


def _registrable(domain: str) -> str:
    """Naive eTLD+1 (good enough for a lab; swap for `tldextract` in prod)."""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


def _is_lookalike(domain: str, protected: set[str]) -> bool:
    reg = _registrable(domain)
    label = reg.split(".")[0]
    for p in protected:
        if reg == p:
            return False
        p_label = p.split(".")[0]
        normalized = label.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
        if normalized == p_label or (len(p_label) > 4 and _levenshtein(label, p_label) <= 2):
            return True
        # brand embedded in another domain: "contoso-support.com", "contoso.com.evil.io"
        if p_label in domain and reg != p:
            return True
    return False


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------
def score_email(email: Email,
                protected_domains: set[str],
                known_bad_urls: set[str] | None = None) -> Result:
    """
    protected_domains: your org + key partner/brand domains, e.g. {"contoso.com", "microsoft.com"}
    known_bad_urls:    optional enrichment result (URLs a TI feed flagged as malicious)
    """
    signals: list[str] = []
    sender_domain = _domain(email.sender_address)

    # --- authentication -------------------------------------------------
    if email.spf.lower() in {"fail", "softfail"}:
        signals.append("spf_fail")
    if email.dkim.lower() == "fail":
        signals.append("dkim_fail")
    if email.dmarc.lower() == "fail":
        signals.append("dmarc_fail")

    # --- sender identity --------------------------------------------------
    if email.reply_to and _registrable(_domain(email.reply_to)) != _registrable(sender_domain):
        signals.append("reply_to_mismatch")

    name = email.sender_display_name.lower()
    for p in protected_domains:
        brand = p.split(".")[0]
        if brand in name and _registrable(sender_domain) != p:
            signals.append("display_name_spoof")
            break

    if _is_lookalike(sender_domain, protected_domains):
        signals.append("lookalike_domain")

    if email.first_time_sender:
        signals.append("first_time_sender")

    # --- links ------------------------------------------------------------
    link_signals: set[str] = set()
    for link in email.links:
        host = _domain(link.url)
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            link_signals.add("raw_ip_url")
        if host in SHORTENERS:
            link_signals.add("url_shortener")
        shown = link.display_text.strip()
        if shown and re.search(r"[a-z0-9-]+\.[a-z]{2,}", shown, re.I):
            if _registrable(_domain(shown)) != _registrable(host):
                link_signals.add("link_text_mismatch")
        if _is_lookalike(host, protected_domains):
            link_signals.add("lookalike_domain")
        if known_bad_urls and link.url in known_bad_urls:
            link_signals.add("known_bad_url")
    for s in sorted(link_signals):
        if s not in signals:
            signals.append(s)

    # --- attachments ----------------------------------------------------
    for name_ in email.attachments:
        ext = "." + name_.lower().rsplit(".", 1)[-1] if "." in name_ else ""
        # double extension like invoice.pdf.exe
        if ext in RISKY_EXTENSIONS and "risky_attachment" not in signals:
            signals.append("risky_attachment")
        if ext in MACRO_EXTENSIONS and "macro_attachment" not in signals:
            signals.append("macro_attachment")

    # --- content --------------------------------------------------------
    text = f"{email.subject}\n{email.body}"
    if CREDENTIAL_PATTERNS.search(text):
        signals.append("credential_lure")
    if URGENCY_PATTERNS.search(text):
        signals.append("urgency_language")

    score = min(100, sum(WEIGHTS[s] for s in signals))
    if score >= MALICIOUS_THRESHOLD:
        verdict = "malicious"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "benign"
    return Result(score=score, verdict=verdict, signals=signals)


def email_from_sentinel_entities(entities: list[dict]) -> Email | None:
    """
    Map Microsoft Sentinel / Defender 'MailMessage' + 'Url' + 'File' entities
    (as delivered in the incident trigger payload) to an Email record.
    Field names follow the Sentinel entity schema; missing fields default safely.
    """
    mail = next((e for e in entities if (e.get("kind") or e.get("Type", "")).lower() in
                 {"mailmessage", "mail-message"}), None)
    if not mail:
        return None
    props = mail.get("properties", mail)
    urls = [e.get("properties", e).get("url", "") for e in entities
            if (e.get("kind") or e.get("Type", "")).lower() == "url"]
    files = [e.get("properties", e).get("fileName", "") for e in entities
             if (e.get("kind") or e.get("Type", "")).lower() == "file"]
    auth = (props.get("authenticationDetails") or {})
    return Email(
        sender_address=props.get("p2Sender") or props.get("sender") or "",
        sender_display_name=props.get("p2SenderDisplayName") or props.get("senderDisplayName") or "",
        reply_to=props.get("replyTo", ""),
        subject=props.get("subject", ""),
        body="",  # body is not in the entity; content signals use the subject only
        links=[Link(u) for u in urls if u],
        attachments=[f for f in files if f],
        spf=str(auth.get("SPF", "none")).lower(),
        dkim=str(auth.get("DKIM", "none")).lower(),
        dmarc=str(auth.get("DMARC", "none")).lower(),
    )
