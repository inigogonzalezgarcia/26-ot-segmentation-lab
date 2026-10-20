"""Outputs: report.html (with a Purdue diagram), review.md, firewall-proposal.csv, zone-matrix.csv, actions.csv, findings.csv."""
from __future__ import annotations

import csv
import html
from collections import defaultdict
from pathlib import Path

from .checks import AREAS, CRITICAL, INFO, INTERNET, SEV_ORDER, WARNING, Finding, proposal, zone_matrix
from .model import DMZ_LEVEL, Site, service_name

e = html.escape


def area_status(findings: list[Finding]) -> dict[str, str]:
    st = {}
    for a in AREAS:
        sev = [f.severity for f in findings if f.area == a]
        st[a] = min(sev, key=SEV_ORDER.get) if sev else "ok"
    return st


def summary(site: Site, findings: list[Finding], rows: list[dict]) -> dict:
    crossing = [r for r in rows]
    return {"zones": len(site.zones), "assets": len(site.assets), "rules": len(site.rules), "flows": len(site.flows),
            "crossing": len(crossing), "clean": sum(not r["worst"] for r in crossing),
            "critical": sum(f.severity == CRITICAL for f in findings), "warning": sum(f.severity == WARNING for f in findings),
            "info": sum(f.severity == INFO for f in findings)}


def write_findings(findings: list[Finding], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "area", "code", "ref", "subject", "owner", "zones", "detail", "next_step"])
        for f in findings:
            w.writerow([f.severity, f.area, f.code, f.ref, f.subject, f.owner, " ".join(f.zones), f.detail, f.fix])


def write_actions(findings: list[Finding], site: Site, path: Path) -> int:
    rows = [f for f in findings if f.severity != INFO]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["priority", "severity", "owner", "subject", "action", "why", "done"])
        for i, f in enumerate(rows, 1):
            owner = f.owner or next((z.owner for z in site.zones if z.id in f.zones and z.owner), "")
            w.writerow([i, f.severity, owner, f.subject, f.fix, f.detail, ""])
    return len(rows)


def write_proposal(site: Site, rows: list[dict], path: Path) -> int:
    props = proposal(site, rows)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["action", "src_zone", "dst_zone", "src", "dst", "service", "name", "sessions", "existing_rule", "reasons"])
        for p in props:
            w.writerow([p["action"], p["src_zone"], p["dst_zone"], p["src"], p["dst"], p["service"], p["name"], p["sessions"],
                        p["existing_rule"], p["reasons"]])
    return len(props)


def write_matrix(site: Site, rows: list[dict], path: Path) -> None:
    m = zone_matrix(site, rows)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["src_zone", "dst_zone", "rules", "observed_flows", "sessions", "critical_flows", "warning_flows"])
        for (a, b), c in sorted(m.items()):
            w.writerow([a, b, c["rules"], c["flows"], c["sessions"], c["critical"], c["warning"]])


def review_md(site: Site, findings: list[Finding], rows: list[dict]) -> str:
    sm = summary(site, findings, rows)
    out = [f"# OT segmentation review · {site.organisation} · {site.site}", "",
           f"As of {site.as_of.isoformat()}: {sm['zones']} zones, {sm['assets']} assets, {sm['rules']} conduits, "
           f"{sm['crossing']} observed flows across zones ({sm['clean']} clean). "
           f"{sm['critical']} critical, {sm['warning']} warnings.", "", "## Fix first", ""]
    out += [f"- **{f.subject}** ({f.area}): {f.detail} → {f.fix}" for f in findings if f.severity == CRITICAL] or ["- Nothing critical."]
    out += ["", "## This month", ""]
    out += [f"- {f.subject}: {f.fix}" for f in findings if f.severity == WARNING] or ["- Nothing."]
    out += ["", "## For the record", ""]
    out += [f"- {f.subject}: {f.detail}" for f in findings if f.severity == INFO] or ["- Nothing."]
    out += ["", "## Conduit changes to discuss", ""]
    for p in proposal(site, rows):
        if p["action"] != "allow":
            out.append(f"- {p['action']}: {p['src']} → {p['dst']} {p['name']} ({p['sessions']} sessions)")
    return "\n".join(out) + "\n"


CSS = """
:root{--bg:#f6f7f8;--card:#fff;--ink:#1b2128;--muted:#66717c;--line:#e2e5e9;--ok:#1e7a4c;--warn:#a46200;--bad:#b42318;--info:#0b6bcb;--na:#8a94a0;--band:#eef1f4}
@media (prefers-color-scheme:dark){:root{--bg:#13171b;--card:#1b2127;--ink:#e7eaee;--muted:#9aa5b0;--line:#2b333b;--ok:#4cc38a;--warn:#f0a83a;--bad:#f2685c;--info:#5aa9f0;--na:#6d7782;--band:#20272e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:26px}
.areas{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.area{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--ok);border-radius:10px;padding:10px 14px}
.area.critical{border-left-color:var(--bad)}.area.warning{border-left-color:var(--warn)}.area.info{border-left-color:var(--info)}
.area .lbl{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-bottom:4px}.area .cnt{display:block;font-size:13px;color:var(--muted);margin-top:4px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pill{display:inline-block;white-space:nowrap;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.critical,.block{color:var(--bad)}.warning,.review,.reroute{color:var(--warn)}.info{color:var(--info)}.ok,.allow{color:var(--ok)}
.area.critical,.area.warning,.area.info,.area.ok{color:inherit}td.nw{white-space:nowrap}td.fix{font-size:13px;color:var(--muted);max-width:380px}
.diagram{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px}.diagram svg{width:100%;height:auto;display:block}
svg .band{fill:var(--band)}svg .lvl{fill:var(--muted);font-size:12px;font-weight:600}svg .zone{fill:var(--card);stroke:var(--line);stroke-width:1.5}
svg .zone.critical{stroke:var(--bad);stroke-width:2.5}svg .zone.warning{stroke:var(--warn);stroke-width:2.5}
svg .zn{fill:var(--ink);font-size:13px;font-weight:600}svg .zs{fill:var(--muted);font-size:11px}
svg .edge{fill:none;stroke-width:2;opacity:.85}svg .edge.ok{stroke:var(--ok)}svg .edge.warning{stroke:var(--warn)}svg .edge.critical{stroke:var(--bad);stroke-dasharray:6 4}
.legend span{display:inline-block;margin-right:14px;font-size:13px}.legend i{display:inline-block;width:18px;height:3px;margin-right:6px;vertical-align:3px}
.legend .ok{background:var(--ok)}.legend .warning{background:var(--warn)}.legend .critical{background:var(--bad)}
footer{margin-top:40px;font-size:13px}
"""

LABELS = {"allow": "Allow", "review": "Review", "block": "Block", "re-route via DMZ": "Re-route via DMZ"}


def _pill(s: str) -> str:
    cls = "reroute" if s.startswith("re-route") else s
    return f"<span class='pill {cls}'>{e(LABELS.get(s) or ('OK' if s == 'ok' else s.upper()))}</span>"


def diagram(site: Site, findings: list[Finding], rows: list[dict]) -> str:
    """Purdue-style picture: one band per level, zones as boxes, observed traffic between zones as coloured lines.
    Neighbouring levels are joined straight down; traffic that skips a level runs along lanes on the right."""
    levels = [5.0] + sorted({z.level for z in site.zones}, reverse=True)
    W, BH, LX, RX = 960, 92, 70, 770
    zone_sev = defaultdict(lambda: "ok")
    for f in findings:
        if f.severity in (CRITICAL, WARNING):
            for zid in f.zones:
                if SEV_ORDER[f.severity] < SEV_ORDER.get(zone_sev[zid], 9):
                    zone_sev[zid] = f.severity
    box, lvl_of = {}, {}
    for i, lvl in enumerate(levels):
        y = 5 + i * BH
        items = ([(INTERNET, "Internet / vendors", "outside every zone")] if lvl == 5.0
                 else [(z.id, z.name, z.subnet) for z in site.zones if z.level == lvl])
        n = max(1, len(items))
        bw = min(220, (RX - LX) / n - 16)
        for j, it in enumerate(items):
            cx = LX + (RX - LX) * (j + 0.5) / n
            box[it[0]] = (cx - bw / 2, y + 14, bw, BH - 36, it)
            lvl_of[it[0]] = i
    edges: dict[tuple[str, str], str] = {}
    for r in rows:
        a_, b_ = r["src_zone"], r["dst_zone"]
        if a_ not in box or b_ not in box:
            continue
        k = tuple(sorted((a_, b_), key=lambda z: lvl_of[z]))
        sev = r["worst"] or "ok"
        if k not in edges or SEV_ORDER.get(sev, 9) < SEV_ORDER.get(edges[k], 9):
            edges[k] = sev
    order = sorted(edges, key=lambda k: (lvl_of[k[1]] - lvl_of[k[0]], lvl_of[k[0]], box[k[0]][0]))
    bottoms, tops = defaultdict(list), defaultdict(list)
    for k in order:
        bottoms[k[0]].append(k)
        tops[k[1]].append(k)
    for zid in bottoms:
        bottoms[zid].sort(key=lambda k: (box[k[1]][0], lvl_of[k[1]]))
    for zid in tops:
        tops[zid].sort(key=lambda k: (box[k[0]][0], lvl_of[k[0]]))

    def slot(zid, lst, k):
        x, _, w, _, _ = box[zid]
        return x + w * (lst.index(k) + 1) / (len(lst) + 1)

    used = defaultdict(int)

    def gutter(i):  # y for the next horizontal run in the gap under level i
        used[i] += 1
        return 5 + i * BH + 70 + 5 * used[i]

    H = BH * len(levels) + 10
    h = [f"<svg viewBox='0 0 {W} {H}' role='img' aria-label='Zones and observed traffic by Purdue level'>"]
    for i, lvl in enumerate(levels):
        y = 5 + i * BH
        name = "Outside" if lvl == 5.0 else ("DMZ" if lvl == DMZ_LEVEL else f"L{lvl:g}")
        h.append(f"<rect class='band' x='0' y='{y}' width='{W}' height='{BH - 8}' rx='8'/><text class='lvl' x='14' y='{y + BH / 2}'>{name}</text>")
    lane = RX + 4
    for k in order:
        (_, ay, _, ah, _), (_, by, _, _, _) = box[k[0]], box[k[1]]
        x1, x2 = slot(k[0], bottoms[k[0]], k), slot(k[1], tops[k[1]], k)
        g1 = gutter(lvl_of[k[0]])
        if lvl_of[k[1]] - lvl_of[k[0]] == 1:
            d = f"M{x1:.0f},{ay + ah:.0f} V{g1:.0f} H{x2:.0f} V{by:.0f}"
        else:
            lane += 13
            g2 = gutter(lvl_of[k[1]] - 1)
            d = f"M{x1:.0f},{ay + ah:.0f} V{g1:.0f} H{lane:.0f} V{g2:.0f} H{x2:.0f} V{by:.0f}"
        h.append(f"<path class='edge {edges[k]}' d='{d}'/>")
    for zid, (x, y, w, hh, (_, name, sub)) in box.items():
        h.append(f"<rect class='zone {zone_sev[zid] if zid != INTERNET else 'ok'}' x='{x:.0f}' y='{y:.0f}' width='{w:.0f}' height='{hh:.0f}' rx='8'/>"
                 f"<text class='zn' x='{x + 12:.0f}' y='{y + 24:.0f}'>{e(name)}</text><text class='zs' x='{x + 12:.0f}' y='{y + 42:.0f}'>{e(sub)}</text>")
    h.append("</svg>")
    return "".join(h)


def render_html(site: Site, findings: list[Finding], rows: list[dict], title: str) -> str:
    sm, st = summary(site, findings, rows), area_status(findings)
    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>{e(title)}</title><style>{CSS}</style></head><body><main>",
         f"<h1>{e(title)}</h1><p class='muted'>{e(site.organisation)} · {e(site.site)} · flows up to {site.as_of:%d %b %Y}</p>",
         "<div class='tiles'>"]
    tiles = [("Zones", str(sm["zones"]), f"{sm['assets']} assets"), ("Conduits", str(sm["rules"]), "approved firewall rules"),
             ("Flows across zones", f"{sm['clean']}/{sm['crossing']}", "clean"),
             ("Critical", str(sm["critical"]), f"{sm['warning']} warnings · {sm['info']} for information")]
    h += [f"<div class='tile'><span class='muted'>{e(a)}</span><b>{e(b)}</b><span class='muted'>{e(x)}</span></div>" for a, b, x in tiles]
    h.append("</div><h2>Status by area</h2><div class='areas'>")
    for a in AREAS:
        n = sum(f.area == a and f.severity != INFO for f in findings)
        h.append(f"<div class='area {st[a]}'><span class='lbl'>{e(a)}</span>{_pill(st[a])}<span class='cnt'>{n} to act on</span></div>")
    h.append("</div><h2>Zones and observed traffic</h2><div class='diagram'>" + diagram(site, findings, rows) + "</div>")
    h.append("<p class='legend muted'><span><i class='ok'></i>Clean traffic</span><span><i class='warning'></i>Needs review</span>"
             "<span><i class='critical'></i>Breaks the model</span></p>")

    crit = [f for f in findings if f.severity == CRITICAL]
    if crit:
        h.append("<h2>Fix first</h2><div class='wrap'><table><tr><th>Subject</th><th>What</th><th>Next step</th></tr>")
        h += [f"<tr><td><b>{e(f.subject)}</b><br><span class='muted'>{e(f.area)}</span></td><td>{e(f.detail)}</td>"
              f"<td class='fix'>{e(f.fix)}</td></tr>" for f in crit]
        h.append("</table></div>")

    m = zone_matrix(site, rows)
    h.append("<h2>Zone to zone</h2><div class='wrap'><table><tr><th>From</th><th>To</th><th class='num'>Conduits</th>"
             "<th class='num'>Flows</th><th class='num'>Sessions</th><th>Status</th></tr>")
    for (a, b), c in sorted(m.items(), key=lambda kv: (-kv[1]["critical"], -kv[1]["warning"], kv[0])):
        s = "critical" if c["critical"] else "warning" if c["warning"] else ("ok" if c["flows"] else "info")
        lab = _pill(s) if c["flows"] else "<span class='muted'>no traffic</span>"
        h.append(f"<tr><td>{e(a)}</td><td>{e(b)}</td><td class='num'>{c['rules']}</td><td class='num'>{c['flows']}</td>"
                 f"<td class='num'>{c['sessions']:,}</td><td>{lab}</td></tr>")
    h.append("</table></div>")

    h.append("<h2>Proposed conduits from observed traffic</h2><p class='muted'>One line per host pair and service, "
             "so the rule set can be tightened to what the plant actually uses.</p><div class='wrap'><table><tr><th>Action</th>"
             "<th>From</th><th>To</th><th>Service</th><th class='num'>Sessions</th><th>Today</th></tr>")
    for p in proposal(site, rows):
        h.append(f"<tr><td>{_pill(p['action'])}</td><td>{e(p['src'])}<br><span class='muted'>{e(p['src_zone'])}</span></td>"
                 f"<td>{e(p['dst'])}<br><span class='muted'>{e(p['dst_zone'])}</span></td><td class='nw'>{e(p['name'])}</td>"
                 f"<td class='num'>{p['sessions']:,}</td><td class='nw'>{e(p['existing_rule'] or 'no rule')}</td></tr>")
    h.append("</table></div>")

    h.append("<h2>Conduits</h2><div class='wrap'><table><tr><th>Rule</th><th>From → To</th><th>Service</th><th>Purpose</th><th>Approved by</th></tr>")
    for r in site.rules:
        exp = f"<br><span class='muted'>until {r.expires.isoformat()}</span>" if r.expires else ""
        h.append(f"<tr><td class='nw'>{e(r.id)}</td><td>{e(r.src_zone)} {e(r.src)} → {e(r.dst_zone)} {e(r.dst)}</td>"
                 f"<td class='nw'>{e(service_name(r.port))}</td><td>{e(r.purpose)}{exp}</td><td>{e(r.approved_by or '–')}</td></tr>")
    h.append("</table></div>")

    rest = [f for f in findings if f.severity != CRITICAL]
    h.append("<h2>Warnings and notes</h2><div class='wrap'><table><tr><th>Severity</th><th>Subject</th><th>What</th><th>Next step</th></tr>")
    h += [f"<tr><td>{_pill(f.severity)}</td><td><b>{e(f.subject)}</b><br><span class='muted'>{e(f.area)}</span></td>"
          f"<td>{e(f.detail)}</td><td class='fix'>{e(f.fix)}</td></tr>" for f in rest]
    h.append("</table></div><footer class='muted'>Built with ot-segmentation-lab · a learning lab with fictional data.</footer></main></body></html>")
    return "".join(h)
