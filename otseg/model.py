"""Load zones, assets, conduits (firewall rules) and observed flows from CSV files."""
from __future__ import annotations

import csv
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

ANY = {"", "*", "any", "all", "cualquiera"}
DMZ_LEVEL = 3.5

# Well-known services by port. "industrial" protocols carry process commands; "cleartext" ones carry admin sessions
# or files without encryption. Both are fine inside a zone and need a reason to cross a zone boundary.
INDUSTRIAL = {502: "Modbus/TCP", 102: "S7comm", 44818: "EtherNet/IP", 2222: "EtherNet/IP I/O", 20000: "DNP3",
              2404: "IEC 60870-5-104", 47808: "BACnet", 34962: "PROFINET", 34964: "PROFINET"}
CLEARTEXT = {21: "FTP", 23: "Telnet", 80: "HTTP", 139: "NetBIOS", 445: "SMB", 5900: "VNC", 161: "SNMP"}
REMOTE_ADMIN = {3389: "RDP", 5900: "VNC", 22: "SSH", 23: "Telnet", 5938: "TeamViewer"}
NAMED = {**INDUSTRIAL, **CLEARTEXT, **REMOTE_ADMIN, 443: "HTTPS", 4840: "OPC UA", 1433: "SQL Server",
         53: "DNS", 123: "NTP", 514: "Syslog", 8443: "HTTPS-alt", 5450: "PI Data Archive"}


def norm(s: str | None) -> str:
    return (s or "").strip()


def parse_date(s: str | None) -> date | None:
    s = norm(s)
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            pass
    return None


def parse_level(s: str | None) -> float | None:
    s = norm(s).upper().replace("L", "").replace(",", ".")
    if s in ("DMZ", "3.5"):
        return DMZ_LEVEL
    try:
        return float(s)
    except ValueError:
        return None


def parse_service(s: str | None) -> tuple[str, int | None]:
    """'tcp/502', '502', 'udp 161', 'any' -> (proto, port). Port None means any."""
    s = norm(s).lower().replace(" ", "/")
    if s in ANY:
        return ("any", None)
    proto, _, port = s.partition("/") if "/" in s else ("tcp", "", s)
    try:
        return (proto or "tcp", int(port))
    except ValueError:
        return (proto or "tcp", None)


def service_name(port: int | None) -> str:
    return "any service" if port is None else NAMED.get(port, f"port {port}")


@dataclass
class Zone:
    id: str
    name: str
    level: float
    subnet: str = ""
    sl_target: int = 2
    owner: str = ""

    @property
    def net(self):
        try:
            return ipaddress.ip_network(self.subnet, strict=False) if self.subnet else None
        except ValueError:
            return None

    @property
    def label(self) -> str:
        return "DMZ" if self.level == DMZ_LEVEL else f"L{self.level:g}"


@dataclass
class Asset:
    id: str
    name: str
    type: str
    zone: str
    ip: str
    os: str = ""
    criticality: str = "medium"
    owner: str = ""


@dataclass
class Rule:
    id: str
    src_zone: str
    dst_zone: str
    src: str
    dst: str
    proto: str
    port: int | None
    purpose: str = ""
    approved_by: str = ""
    expires: date | None = None


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    proto: str
    port: int | None
    count: int = 1
    last_seen: date | None = None


@dataclass
class Site:
    zones: list[Zone]
    assets: list[Asset]
    rules: list[Rule]
    flows: list[Flow]
    organisation: str = ""
    site: str = ""
    as_of: date = field(default_factory=date.today)

    def zone(self, zid: str) -> Zone | None:
        return next((z for z in self.zones if z.id.lower() == zid.lower()), None)

    def asset_by_ip(self, ip: str) -> Asset | None:
        return next((a for a in self.assets if a.ip == ip), None)

    def zone_of_ip(self, ip: str) -> Zone | None:
        a = self.asset_by_ip(ip)
        if a and self.zone(a.zone):
            return self.zone(a.zone)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return next((z for z in self.zones if z.net and addr in z.net), None)


def _rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8-sig")
    delim = ";" if text.splitlines()[0].count(";") > text.splitlines()[0].count(",") else ","
    rows = []
    for r in csv.DictReader(text.splitlines(), delimiter=delim):
        rows.append({norm(k).lower(): norm(v) for k, v in r.items() if k})
    return rows


def g(r: dict, *names: str) -> str:
    for n in names:
        if r.get(n):
            return r[n]
    return ""


def load(folder: Path, as_of: date | None = None) -> Site:
    folder = Path(folder)
    if not (folder / "zones.csv").exists() or not (folder / "assets.csv").exists():
        raise FileNotFoundError(f"{folder} needs zones.csv and assets.csv")
    zones = []
    for r in _rows(folder / "zones.csv"):
        lvl = parse_level(g(r, "level", "purdue_level", "nivel"))
        zones.append(Zone(id=g(r, "zone_id", "zone", "zona"), name=g(r, "name", "nombre") or g(r, "zone_id"),
                          level=lvl if lvl is not None else 4.0, subnet=g(r, "subnet", "subred"),
                          sl_target=int(g(r, "sl_target", "sl_t") or 2), owner=g(r, "owner", "responsable")))
    assets = [Asset(id=g(r, "asset_id", "id"), name=g(r, "name", "nombre"), type=g(r, "type", "tipo").lower(),
                    zone=g(r, "zone", "zona"), ip=g(r, "ip"), os=g(r, "os", "firmware"),
                    criticality=(g(r, "criticality", "criticidad") or "medium").lower(), owner=g(r, "owner", "responsable"))
              for r in _rows(folder / "assets.csv")]
    rules = []
    for r in _rows(folder / "conduits.csv"):
        proto, port = parse_service(g(r, "service", "servicio", "port"))
        rules.append(Rule(id=g(r, "rule_id", "id"), src_zone=g(r, "src_zone", "origen_zona"), dst_zone=g(r, "dst_zone", "destino_zona"),
                          src=g(r, "src", "origen") or "*", dst=g(r, "dst", "destino") or "*", proto=proto, port=port,
                          purpose=g(r, "purpose", "motivo"), approved_by=g(r, "approved_by", "aprobado_por"),
                          expires=parse_date(g(r, "expires", "caduca"))))
    flows = []
    for r in _rows(folder / "flows.csv"):
        proto, port = parse_service(f"{g(r, 'proto', 'protocol') or 'tcp'}/{g(r, 'port', 'dst_port', 'puerto')}")
        flows.append(Flow(src_ip=g(r, "src_ip", "src"), dst_ip=g(r, "dst_ip", "dst"), proto=proto, port=port,
                          count=int(g(r, "count", "sessions") or 1), last_seen=parse_date(g(r, "last_seen"))))
    settings = {}
    if (folder / "settings.json").exists():
        settings = json.loads((folder / "settings.json").read_text(encoding="utf-8"))
    return Site(zones=zones, assets=assets, rules=rules, flows=flows, organisation=settings.get("organisation", ""),
                site=settings.get("site", ""), as_of=as_of or parse_date(settings.get("as_of")) or date.today())
