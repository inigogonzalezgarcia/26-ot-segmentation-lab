"""Command line: `demo` builds everything from a fictional plant, `report` runs on your own CSV exports."""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from . import report, simulate
from .checks import Config, run_all
from .model import load, parse_date


def run(data: Path, out: Path, title: str, c: Config, as_of: date | None = None) -> dict:
    site = load(data, as_of)
    findings, rows = run_all(site, c)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(report.render_html(site, findings, rows, title), encoding="utf-8")
    (out / "review.md").write_text(report.review_md(site, findings, rows), encoding="utf-8")
    report.write_findings(findings, out / "findings.csv")
    report.write_actions(findings, site, out / "actions.csv")
    report.write_proposal(site, rows, out / "firewall-proposal.csv")
    report.write_matrix(site, rows, out / "zone-matrix.csv")
    return report.summary(site, findings, rows)


def _date(value: str) -> date:
    d = parse_date(value)
    if not d:
        raise argparse.ArgumentTypeError(f"not a date (YYYY-MM-DD): {value}")
    return d


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="otseg", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="write the fictional plant to sample_data/ and build the outputs")
    d.add_argument("--data", type=Path, default=Path("sample_data"))
    d.add_argument("--out", type=Path, default=Path("output"))
    r = sub.add_parser("report", help="build the outputs from your own folder of CSV files")
    r.add_argument("data", type=Path, help="folder with zones.csv and assets.csv (and conduits.csv, flows.csv, settings.json)")
    r.add_argument("--out", type=Path, default=Path("output"))
    r.add_argument("--title", default="OT segmentation review")
    r.add_argument("--as-of", type=_date, help="review date, YYYY-MM-DD (default: settings.json or today)")
    r.add_argument("--expiring-days", type=int, default=Config.expiring_days)
    r.add_argument("--no-unused", action="store_true", help="do not report rules with no matching traffic (short flow exports)")
    a = p.parse_args(argv)

    if a.cmd == "demo":
        simulate.write(a.data)
        sm = run(a.data, a.out, "OT segmentation review · Fabrikam Foods", Config())
    else:
        try:
            sm = run(a.data, a.out, a.title, Config(expiring_days=a.expiring_days, unused_rules=not a.no_unused), a.as_of)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    print(f"{sm['zones']} zones · {sm['assets']} assets · {sm['rules']} conduits · {sm['clean']}/{sm['crossing']} flows across zones clean · "
          f"{sm['critical']} critical, {sm['warning']} warnings · outputs in {a.out}/")
    return 0
