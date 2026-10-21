"""
Run the scorer over a labeled JSONL file and report how the triage decisions
would have played out.

Usage:  python src/evaluate.py sample/reported_emails.jsonl
"""
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from triage import Email, Link, score_email  # noqa: E402

PROTECTED = {"contoso.com", "microsoft.com"}


def load(path):
    for line in Path(path).read_text().splitlines():
        rec = json.loads(line)
        label = rec.pop("label")
        rec["links"] = [Link(**l) for l in rec["links"]]
        yield Email(**rec), label


def main(path):
    outcomes = Counter()
    signal_counts = Counter()
    missed = []
    for email, label in load(path):
        r = score_email(email, PROTECTED)
        outcomes[(label, r.verdict)] += 1
        signal_counts.update(r.signals)
        if label == "phish" and r.verdict == "benign":
            missed.append((email.subject, r.score, r.signals))

    total = sum(outcomes.values())
    phish_total = sum(v for (l, _), v in outcomes.items() if l == "phish")
    benign_total = total - phish_total
    auto_closed = sum(v for (_, verdict), v in outcomes.items() if verdict == "benign")
    fn = outcomes[("phish", "benign")]
    fp_escalated = outcomes[("benign", "malicious")]

    print(f"Records: {total}  (phish {phish_total}, benign {benign_total})\n")
    print(f"{'label':<8}{'malicious':>11}{'suspicious':>12}{'benign':>8}")
    for label in ("phish", "benign"):
        print(f"{label:<8}" + "".join(f"{outcomes[(label, v)]:>{w}}"
              for v, w in (("malicious", 11), ("suspicious", 12), ("benign", 8))))
    print()
    print(f"Auto-closed as benign:       {auto_closed} ({auto_closed / total:.0%} of queue)")
    print(f"Phish auto-closed (missed):  {fn}")
    print(f"Benign escalated as malicious: {fp_escalated}")
    print(f"Needs analyst review:        {total - auto_closed}")
    print("\nTop signals:", ", ".join(f"{s}={c}" for s, c in signal_counts.most_common(8)))
    if missed:
        print("\nMissed phish:")
        for m in missed:
            print("  ", m)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample/reported_emails.jsonl")
