import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from triage import Email, Link, score_email, email_from_sentinel_entities  # noqa: E402

PROTECTED = {"contoso.com", "microsoft.com"}


def test_internal_mail_is_benign():
    e = Email("jordan.lee@contoso.com", "Jordan Lee", subject="Lunch Thursday?")
    r = score_email(e, PROTECTED)
    assert r.verdict == "benign" and r.score == 0


def test_lookalike_sender_with_credential_lure_is_malicious():
    e = Email("it-support@c0ntoso.com", "Contoso IT",
              subject="Action required: verify your account",
              links=[Link("http://203.0.113.45/login", "Sign in")], spf="fail", dmarc="fail")
    r = score_email(e, PROTECTED)
    assert r.verdict == "malicious"
    for s in ("lookalike_domain", "display_name_spoof", "raw_ip_url", "credential_lure", "dmarc_fail"):
        assert s in r.signals


def test_link_text_mismatch():
    e = Email("news@example.org", links=[Link("http://evil.example.net/x", "https://login.contoso.com")])
    assert "link_text_mismatch" in score_email(e, PROTECTED).signals


def test_brand_embedded_domain_is_lookalike():
    e = Email("admin@contoso.com.secure-login.net")
    assert "lookalike_domain" in score_email(e, PROTECTED).signals


def test_legit_vendor_with_matching_link_text_is_benign():
    e = Email("billing@fabrikam.com", "Fabrikam Billing", subject="Invoice #1042 attached",
              links=[Link("https://portal.fabrikam.com/inv/1042", "portal.fabrikam.com")],
              attachments=["invoice.pdf"])
    assert score_email(e, PROTECTED).verdict == "benign"


def test_html_smuggling_and_macro_attachments():
    e = Email("x@example.net", attachments=["Invoice_Q4.pdf.html", "payroll.xlsm"])
    s = score_email(e, PROTECTED).signals
    assert "risky_attachment" in s and "macro_attachment" in s


def test_known_bad_url_enrichment_forces_escalation():
    url = "https://docs.example.com/share/abc"
    e = Email("someone@example.com", links=[Link(url)])
    assert score_email(e, PROTECTED).verdict == "benign"
    assert score_email(e, PROTECTED, known_bad_urls={url}).verdict == "malicious"


def test_score_capped_at_100():
    e = Email("security@c0ntoso.com", "Contoso Security", reply_to="a@example.net",
              subject="URGENT: verify your password immediately",
              links=[Link("http://198.51.100.7/a", "https://login.contoso.com"), Link("https://bit.ly/x")],
              attachments=["a.iso", "b.docm"], spf="fail", dkim="fail", dmarc="fail", first_time_sender=True)
    assert score_email(e, PROTECTED).score == 100


def test_sentinel_entity_mapping():
    entities = [
        {"kind": "MailMessage", "properties": {
            "p2Sender": "helpdesk@contosso.com", "p2SenderDisplayName": "Contoso Helpdesk",
            "subject": "Unusual sign-in activity detected",
            "authenticationDetails": {"SPF": "Fail", "DKIM": "None", "DMARC": "Fail"}}},
        {"kind": "Url", "properties": {"url": "http://203.0.113.45/o365"}},
        {"kind": "File", "properties": {"fileName": "statement.lnk"}},
    ]
    email = email_from_sentinel_entities(entities)
    assert email.sender_address == "helpdesk@contosso.com"
    assert email.spf == "fail" and email.attachments == ["statement.lnk"]
    assert score_email(email, PROTECTED).verdict == "malicious"


def test_no_mail_entity_returns_none():
    assert email_from_sentinel_entities([{"kind": "Ip", "properties": {"address": "203.0.113.9"}}]) is None
