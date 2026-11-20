import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from triage import Email, Link, score_email  # noqa: E402
from triage.expand import expand_links, is_safe_target, make_http_resolver  # noqa: E402

PROTECTED = {"contoso.com"}


def test_resolved_url_is_scored_but_shortener_signal_kept():
    e = Email("ar@vendor.example", links=[Link("https://bit.ly/abc", "Pay invoice",
                                              resolved_url="http://203.0.113.9/pay")])
    s = score_email(e, PROTECTED).signals
    assert "url_shortener" in s and "raw_ip_url" in s


def test_known_bad_matches_resolved_url():
    e = Email("ar@vendor.example", links=[Link("https://bit.ly/abc", "",
                                              resolved_url="http://bad.example.net/x")])
    r = score_email(e, PROTECTED, known_bad_urls={"http://bad.example.net/x"})
    assert "known_bad_url" in r.signals and r.verdict == "malicious"


def test_expand_only_touches_shorteners_and_uses_resolver():
    calls = []

    def fake(url):
        calls.append(url)
        return "http://evil.example.net/login"

    e = Email("a@b.example", links=[Link("https://bit.ly/x", "t"), Link("https://contoso.com/p", "t")])
    out = expand_links(e, fake)
    assert calls == ["https://bit.ly/x"]
    assert out.links[0].resolved_url == "http://evil.example.net/login"
    assert out.links[1].resolved_url == ""
    assert e.links[0].resolved_url == ""  # input not mutated


def test_expand_caps_number_of_lookups_and_survives_resolver_errors():
    def boom(url):
        raise OSError("timeout")

    links = [Link(f"https://bit.ly/{i}") for i in range(10)]
    out = expand_links(Email("a@b.example", links=links), boom, max_links=3)
    assert all(l.resolved_url == "" for l in out.links)


def test_unsafe_targets_rejected():
    for u in ("http://127.0.0.1/", "http://10.0.0.5/x", "http://169.254.169.254/latest",
              "http://[::1]/", "ftp://bit.ly/x", "file:///etc/passwd", "http://localhost/"):
        assert not is_safe_target(u), u
    assert is_safe_target("https://bit.ly/abc", resolve=lambda h: ["93.184.216.34"])
    assert not is_safe_target("https://bit.ly/abc", resolve=lambda h: ["10.1.2.3"])


def test_http_resolver_follows_redirects_with_limit_and_blocks_unsafe_hops():
    hops = {"https://bit.ly/a": "https://t.example/b",
            "https://t.example/b": "http://final.example.net/x",
            "http://final.example.net/x": None}

    def head(url):
        return hops[url]

    r = make_http_resolver(head=head, resolve=lambda h: ["93.184.216.34"], max_hops=5)
    assert r("https://bit.ly/a") == "http://final.example.net/x"

    loop = {"https://a.example/": "https://b.example/", "https://b.example/": "https://a.example/"}
    r2 = make_http_resolver(head=lambda u: loop[u], resolve=lambda h: ["93.184.216.34"], max_hops=3)
    assert r2("https://a.example/") in ("https://a.example/", "https://b.example/")

    internal = {"https://bit.ly/a": "http://169.254.169.254/latest"}
    r3 = make_http_resolver(head=lambda u: internal.get(u), resolve=lambda h: ["93.184.216.34"])
    assert r3("https://bit.ly/a") == "https://bit.ly/a"  # refuses to follow into private space


def test_known_bad_original_url_still_matches_after_expansion():
    # Lab QA finding: expansion must add evidence, never remove it.
    e = Email("ar@vendor.example", links=[Link("https://bit.ly/abc", "",
                                              resolved_url="http://clean.example.net/ok")])
    r = score_email(e, PROTECTED, known_bad_urls={"https://bit.ly/abc"})
    assert "known_bad_url" in r.signals and r.verdict == "malicious"


def test_original_link_lookalike_evidence_survives_expansion():
    e = Email("ar@vendor.example", links=[Link("http://c0ntoso.com/login", "",
                                              resolved_url="http://clean.example.net/ok")])
    assert "lookalike_domain" in score_email(e, PROTECTED).signals


def test_expansion_never_lowers_the_score():
    base = Email("ar@vendor.example", links=[Link("https://bit.ly/abc", "https://contoso.com")])
    expanded = Email("ar@vendor.example", links=[Link("https://bit.ly/abc", "https://contoso.com",
                                                      resolved_url="http://clean.example.net/ok")])
    assert score_email(expanded, PROTECTED).score >= score_email(base, PROTECTED).score
