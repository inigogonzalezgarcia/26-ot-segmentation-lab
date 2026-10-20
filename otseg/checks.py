"""Checks: conduits (firewall rules), observed traffic, remote access, assets and data quality."""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from .model import ANY, CLEARTEXT, DMZ_LEVEL, INDUSTRIAL, REMOTE_ADMIN, Flow, Rule, Site, Zone, service_name

CRITICAL, WARNING, INFO = "critical", "warning", "info"
SEV_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}
AREAS = ["Conduits", "Traffic", "Remote access", "Assets", "Data quality"]
EOL_OS = ("windows xp", "windows 7", "windows 2000", "windows server 2003", "windows server 2008", "windows nt")
INTERNET = "Internet"


@dataclass
class Config:
    expiring_days: int = 14
    unused_rules: bool = True


@dataclass
class Finding:
    severity: str
    area: str
    code: str
    subject: str
    detail: str
    fix: str
    ref: str = ""
    owner: str = ""
    zones: tuple[str, ...] = field(default_factory=tuple)


def is_ot(z: Zone | None) -> bool:
    return z is not None and z.level <= 3


def path_issue(a: Zone | None, b: Zone | None) -> str:
    """Why traffic between two zones breaks the layered model, or '' if the path is fine."""
    if a is None or b is None or a.id == b.id:
        return ""
    lo, hi = sorted((a, b), key=lambda z: z.level)
    if hi.level >= 4 and lo.level <= 3:
        return f"connects {hi.name} ({hi.label}) straight to {lo.name} ({lo.label}), bypassing the IT/OT DMZ"
    if hi.level == DMZ_LEVEL and lo.level < 3:
        return f"connects the DMZ straight to {lo.name} ({lo.label}); the DMZ should only reach site operations (L3)"
    if hi.level <= 3 and hi.level - lo.level > 1:
        return f"connects {hi.name} ({hi.label}) to {lo.name} ({lo.label}), skipping a level"
    return ""


def path_fix(a: Zone | None, b: Zone | None) -> str:
    lo, hi = sorted((a, b), key=lambda z: z.level)
    if hi.level >= 4:
        return "Route it through the DMZ (a historian mirror, a file transfer server or the jump host) and remove the direct path."
    if hi.level == DMZ_LEVEL:
        return "End DMZ sessions on a host in site operations (L3) and go down to the cell from there."
    return f"Go through {lo.name}'s supervisory zone (L2), for example by moving the engineering station into the cell."


def _host_match(spec: str, ip: str, site: Site) -> bool:
    spec = spec.strip()
    if spec.lower() in ANY:
        return True
    a = site.asset_by_ip(ip)
    if a and spec.lower() in (a.id.lower(), a.name.lower()):
        return True
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return False


def rule_matches(rule: Rule, flow: Flow, site: Site) -> bool:
    zs, zd = site.zone_of_ip(flow.src_ip), site.zone_of_ip(flow.dst_ip)
    src_zone = zs.id if zs else INTERNET
    dst_zone = zd.id if zd else INTERNET
    return (rule.src_zone.lower() == src_zone.lower() and rule.dst_zone.lower() == dst_zone.lower()
            and _host_match(rule.src, flow.src_ip, site) and _host_match(rule.dst, flow.dst_ip, site)
            and (rule.proto == "any" or rule.proto == flow.proto) and (rule.port is None or rule.port == flow.port))


def host_label(site: Site, ip: str) -> str:
    a = site.asset_by_ip(ip)
    return f"{a.name} ({ip})" if a else ip


def _zone_or_external(site: Site, zid: str) -> Zone | None:
    return None if zid.lower() == INTERNET.lower() else site.zone(zid)


# ---------------------------------------------------------------- conduits
def check_rules(site: Site, flows_by_rule: dict[str, int], c: Config) -> list[Finding]:
    out = []
    for r in site.rules:
        zs, zd = _zone_or_external(site, r.src_zone), _zone_or_external(site, r.dst_zone)
        subj = f"{r.id}: {r.src_zone} → {r.dst_zone} {service_name(r.port)}"
        names = tuple(z.id for z in (zs, zd) if z)
        for zid, z in ((r.src_zone, zs), (r.dst_zone, zd)):
            if z is None and zid.lower() != INTERNET.lower():
                out.append(Finding(WARNING, "Data quality", "RULE_UNKNOWN_ZONE", subj, f"Zone '{zid}' is not in zones.csv.",
                                   "Fix the zone name or add the zone.", r.id))
        low = min((z.level for z in (zs, zd) if z), default=9)
        if r.port is None and r.src_zone != r.dst_zone:
            out.append(Finding(CRITICAL if low <= 2 else WARNING, "Conduits", "RULE_ANY_SERVICE", subj,
                               "The rule allows every port and protocol between the two zones.",
                               "Replace it with one rule per service that is actually used (see firewall-proposal.csv).", r.id, zones=names))
        if (r.src.lower() in ANY or r.dst.lower() in ANY) and low <= 2 and r.port is not None:
            out.append(Finding(WARNING, "Conduits", "RULE_ANY_HOST", subj,
                               "Any host on one side can use the conduit into the control network.",
                               "Name the source and destination hosts.", r.id, zones=names))
        issue = path_issue(zs, zd)
        if issue:
            out.append(Finding(CRITICAL, "Conduits", "RULE_PATH", subj, f"The rule {issue}.",
                               path_fix(zs, zd), r.id, zones=names))
        if r.expires and r.expires < site.as_of:
            out.append(Finding(WARNING, "Conduits", "RULE_EXPIRED", subj,
                               f"Temporary rule expired on {r.expires.isoformat()} and is still in place.",
                               "Remove it, or renew it with a new approval and end date.", r.id, zones=names))
        elif r.expires and r.expires <= site.as_of + timedelta(days=c.expiring_days):
            out.append(Finding(INFO, "Conduits", "RULE_EXPIRING", subj, f"Temporary rule ends on {r.expires.isoformat()}.",
                               "Confirm the work is finished and remove the rule on that date.", r.id, zones=names))
        if not r.approved_by:
            out.append(Finding(WARNING, "Conduits", "RULE_NO_APPROVAL", subj, "Nobody is recorded as approving this conduit.",
                               "Record the owner of the OT zone as approver, or remove the rule.", r.id, zones=names))
        if c.unused_rules and not flows_by_rule.get(r.id):
            out.append(Finding(INFO, "Conduits", "RULE_UNUSED", subj, "No traffic matched this rule in the flow export.",
                               "If nothing needs it over a full production cycle, remove it.", r.id, zones=names))
    return out


# ---------------------------------------------------------------- traffic and remote access
def check_flows(site: Site) -> tuple[list[Finding], dict[str, int], list[dict]]:
    out, flows_by_rule, rows = [], defaultdict(int), []
    unknown_seen = set()
    jump_hosts = {a.ip for a in site.assets if "jump" in a.type}
    for f in site.flows:
        zs, zd = site.zone_of_ip(f.src_ip), site.zone_of_ip(f.dst_ip)
        for ip, z in ((f.src_ip, zs), (f.dst_ip, zd)):
            if z and not site.asset_by_ip(ip) and ip not in unknown_seen:
                unknown_seen.add(ip)
                out.append(Finding(WARNING if z.level > 2 else CRITICAL, "Assets", "UNKNOWN_HOST", f"{ip} in {z.name}",
                                   f"{ip} sends or receives traffic in {z.name} ({z.label}) but is not in the asset inventory.",
                                   "Find the device (switch port, MAC address), add it to the inventory or remove it.", ip, zones=(z.id,)))
        if zs is not None and zd is not None and zs.id == zd.id:
            continue
        matched = [r for r in site.rules if rule_matches(r, f, site)]
        for r in matched:
            flows_by_rule[r.id] += f.count
        src, dst = host_label(site, f.src_ip), host_label(site, f.dst_ip)
        subj = f"{src} → {dst} {service_name(f.port)}"
        names = tuple(z.id for z in (zs, zd) if z)
        bad = []
        if zd is None and zs is not None:
            if zs.level <= 3:
                bad.append(Finding(CRITICAL, "Traffic", "OT_TO_INTERNET", subj,
                                   f"A device in {zs.name} ({zs.label}) talks to an address outside every zone ({f.count} sessions).",
                                   "Block it at the OT firewall; if it needs updates, serve them from the DMZ.", zones=names))
            elif zs.level == DMZ_LEVEL:
                bad.append(Finding(WARNING, "Traffic", "DMZ_TO_INTERNET", subj, "The DMZ talks straight to the internet.",
                                   "Send it through the enterprise proxy or remove it.", zones=names))
        remote = f.port in REMOTE_ADMIN and is_ot(zd) and f.src_ip not in jump_hosts and (zs is None or zs.level > 3 or zs.id != zd.id)
        if remote and (zs is None or zs.level >= 4):
            bad.append(Finding(CRITICAL, "Remote access", "REMOTE_NOT_VIA_JUMP", subj,
                               f"{REMOTE_ADMIN[f.port]} into {zd.name} ({zd.label}) from {zs.name if zs else 'outside the site'}, not from the DMZ jump host.",
                               "Force remote sessions through the jump host with MFA and session recording; block the direct path.", zones=names))
        issue = path_issue(zs, zd)
        if not matched and not (zd is None and zs is not None and zs.level <= 3):
            why = f" It also {issue}." if issue else ""
            bad.append(Finding(CRITICAL, "Traffic", "NO_CONDUIT", subj,
                               f"{f.count} sessions crossed from {zs.name if zs else 'outside'} to {zd.name if zd else 'outside'} with no approved conduit.{why}",
                               "Find which firewall rule lets it through; approve it as a conduit or block it.", zones=names))
        elif issue and not remote:
            bad.append(Finding(CRITICAL, "Traffic", "PATH_VIOLATION", subj, f"Allowed by {', '.join(r.id for r in matched)}, but it {issue}.",
                               path_fix(zs, zd), ",".join(r.id for r in matched), zones=names))
        dst_asset = site.asset_by_ip(f.dst_ip)
        if dst_asset and ("safety" in dst_asset.type or dst_asset.type == "sis") and f.port in INDUSTRIAL:
            bad.append(Finding(CRITICAL, "Traffic", "SIS_REACHABLE", subj,
                               f"{INDUSTRIAL[f.port]} reaches the safety system {dst_asset.name} from {zs.name if zs else 'outside'}"
                               f"{' through ' + ', '.join(r.id for r in matched) if matched else ''}.",
                               "Only the safety engineering station should reach the SIS; give other systems read-only data through a gateway.",
                               dst_asset.id, zones=names))
        if f.port in INDUSTRIAL and zs and zd and (zs.level >= 3.5 or abs(zs.level - zd.level) > 1):
            bad.append(Finding(CRITICAL, "Traffic", "INDUSTRIAL_PROTOCOL", subj,
                               f"{INDUSTRIAL[f.port]} has no authentication: a device in {zs.name} can write to the controller.",
                               "Keep controller protocols inside the cell; read process data from the historian or an OPC UA server instead.", zones=names))
        elif f.port in CLEARTEXT and zs and zd:
            bad.append(Finding(WARNING, "Traffic", "CLEARTEXT_PROTOCOL", subj,
                               f"{CLEARTEXT[f.port]} crosses a zone boundary without encryption.",
                               "Use the encrypted version (SSH, HTTPS, SFTP, SNMPv3) or keep it inside the zone.", zones=names))
        out += bad
        worst = min((b.severity for b in bad), key=SEV_ORDER.get, default="")
        rows.append({"flow": f, "src_zone": zs.id if zs else INTERNET, "dst_zone": zd.id if zd else INTERNET,
                     "rules": [r.id for r in matched], "worst": worst, "codes": [b.code for b in bad]})
    return out, flows_by_rule, rows


# ---------------------------------------------------------------- assets
def check_assets(site: Site) -> list[Finding]:
    out = []
    by_zone = defaultdict(list)
    for a in site.assets:
        z = site.zone(a.zone) if a.zone else None
        if z is None:
            out.append(Finding(CRITICAL, "Assets", "NO_ZONE", f"{a.name} ({a.ip})", "The asset is not assigned to a known zone.",
                               "Assign it to a zone; until then nobody owns its conduits.", a.id, a.owner))
            continue
        by_zone[z.id].append(a)
        try:
            if z.net and a.ip and ipaddress.ip_address(a.ip) not in z.net:
                out.append(Finding(WARNING, "Assets", "WRONG_SUBNET", f"{a.name} ({a.ip})",
                                   f"Recorded in {z.name} ({z.subnet}) but its address is outside that subnet.",
                                   "Move it to the right VLAN, or correct the inventory.", a.id, a.owner, (z.id,)))
        except ValueError:
            out.append(Finding(WARNING, "Data quality", "BAD_IP", a.name, f"'{a.ip}' is not an IP address.", "Fix the address.", a.id))
        if any(o in a.os.lower() for o in EOL_OS):
            out.append(Finding(CRITICAL if z.level <= 2 and a.criticality == "high" else WARNING, "Assets", "END_OF_LIFE_OS",
                               f"{a.name} ({a.os})", f"{a.os} gets no security updates; it sits in {z.name} ({z.label}, SL-T {z.sl_target}).",
                               "Keep it, if the process needs it, with compensating controls: its own small zone, allow-list on the conduit, "
                               "no internet, application allow-listing, and a replacement date.", a.id, a.owner, (z.id,)))
        if a.criticality == "high" and not a.owner:
            out.append(Finding(INFO, "Assets", "NO_OWNER", a.name, "High-criticality asset without an owner.", "Name an owner.", a.id, zones=(z.id,)))
    for zid, assets in by_zone.items():
        safety = [a for a in assets if "safety" in a.type or a.type == "sis"]
        control = [a for a in assets if a.type in ("plc", "hmi", "scada", "engineering_ws", "rtu") and a not in safety]
        if safety and control:
            z = site.zone(zid)
            out.append(Finding(CRITICAL, "Assets", "SIS_SHARED_ZONE", f"{z.name}",
                               f"Safety system {', '.join(a.name for a in safety)} shares a zone with {len(control)} control devices.",
                               "Give the safety instrumented system its own zone with a single, read-only conduit.", zid, z.owner, (zid,)))
    return out


def check_zones(site: Site) -> list[Finding]:
    out, seen = [], set()
    for z in site.zones:
        if z.id.lower() in seen:
            out.append(Finding(WARNING, "Data quality", "DUPLICATE_ZONE", z.id, "The zone id appears twice.", "Keep one row per zone.", z.id))
        seen.add(z.id.lower())
        if not z.owner:
            out.append(Finding(INFO, "Data quality", "ZONE_NO_OWNER", z.name, "The zone has no owner to approve its conduits.",
                               "Name an owner (usually the plant or OT manager).", z.id, zones=(z.id,)))
    return out


def run_all(site: Site, c: Config | None = None) -> tuple[list[Finding], list[dict]]:
    c = c or Config()
    flow_findings, flows_by_rule, rows = check_flows(site)
    findings = check_zones(site) + check_rules(site, flows_by_rule, c) + flow_findings + check_assets(site)
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], AREAS.index(f.area), f.code, f.subject))
    return findings, rows


def zone_matrix(site: Site, rows: list[dict]) -> dict[tuple[str, str], dict]:
    m: dict[tuple[str, str], dict] = defaultdict(lambda: {"rules": 0, "flows": 0, "sessions": 0, "critical": 0, "warning": 0})
    for r in site.rules:
        m[(r.src_zone, r.dst_zone)]["rules"] += 1
    for row in rows:
        cell = m[(row["src_zone"], row["dst_zone"])]
        cell["flows"] += 1
        cell["sessions"] += row["flow"].count
        if row["worst"] in (CRITICAL, WARNING):
            cell[row["worst"]] += 1
    return dict(m)


def proposal(site: Site, rows: list[dict]) -> list[dict]:
    """A least-privilege rule set built from what was observed: allow the clean flows host to host, review or block the rest."""
    out: dict[tuple, dict] = {}
    for row in rows:
        f = row["flow"]
        key = (row["src_zone"], row["dst_zone"], f.src_ip, f.dst_ip, f.proto, f.port)
        codes = set(row["codes"])
        action = "review" if codes else "allow"
        if {"REMOTE_NOT_VIA_JUMP", "PATH_VIOLATION"} & codes or ("NO_CONDUIT" in codes and path_issue(
                site.zone_of_ip(f.src_ip), site.zone_of_ip(f.dst_ip))):
            action = "re-route via DMZ"
        if {"OT_TO_INTERNET", "INDUSTRIAL_PROTOCOL", "SIS_REACHABLE"} & codes:
            action = "block"
        cur = out.setdefault(key, {"src_zone": key[0], "dst_zone": key[1], "src": host_label(site, f.src_ip),
                                   "dst": host_label(site, f.dst_ip), "service": f"{f.proto}/{f.port}", "name": service_name(f.port),
                                   "sessions": 0, "action": action, "existing_rule": ",".join(row["rules"]), "reasons": ",".join(row["codes"])})
        cur["sessions"] += f.count
    order = {"block": 0, "re-route via DMZ": 1, "review": 2, "allow": 3}
    return sorted(out.values(), key=lambda r: (order[r["action"]], r["src_zone"], r["dst_zone"], r["src"]))
