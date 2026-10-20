"""Fictional demo site: a bottling plant with two lines, an IT/OT DMZ and a vendor who connects remotely.
Everything here is invented; the gaps are placed on purpose so every check has something to find."""
from __future__ import annotations

import csv
import json
from pathlib import Path

SETTINGS = {"organisation": "Fabrikam Foods", "site": "Guadalajara bottling plant", "as_of": "2026-10-20"}

ZONES = [  # zone_id, name, level, subnet, sl_target, owner
    ("ENT", "Enterprise IT", "4", "10.10.0.0/16", 1, "Laura Gómez"),
    ("DMZ", "IT/OT DMZ", "DMZ", "10.50.0.0/24", 3, "Diego Martín"),
    ("OPS", "Site operations", "3", "10.60.0.0/24", 2, "Diego Martín"),
    ("SUP1", "Line 1 supervisory", "2", "10.70.1.0/24", 2, "Marta Ruiz"),
    ("CTL1", "Line 1 control", "1", "10.80.1.0/24", 3, "Marta Ruiz"),
    ("SUP2", "Line 2 supervisory", "2", "10.70.2.0/24", 2, "Pablo Ortega"),
    ("CTL2", "Line 2 control", "1", "10.80.2.0/24", 3, "Pablo Ortega"),
    ("SIS", "Safety systems", "1", "10.90.0.0/24", 3, ""),
]

ASSETS = [  # asset_id, name, type, zone, ip, os, criticality, owner
    ("A01", "ws-fin-021", "workstation", "ENT", "10.10.4.21", "Windows 11", "low", "Laura Gómez"),
    ("A02", "it-admin-05", "workstation", "ENT", "10.10.3.5", "Windows 11", "medium", "Laura Gómez"),
    ("A03", "erp-app-01", "server", "ENT", "10.10.8.10", "Windows Server 2022", "high", "Laura Gómez"),
    ("A04", "jump-01", "jump_host", "DMZ", "10.50.0.10", "Windows Server 2022", "high", "Diego Martín"),
    ("A05", "hist-mirror", "historian", "DMZ", "10.50.0.20", "Windows Server 2022", "medium", "Diego Martín"),
    ("A06", "patch-01", "server", "DMZ", "10.50.0.30", "Windows Server 2022", "medium", "Diego Martín"),
    ("A07", "sw-core-ot", "switch", "OPS", "10.60.0.2", "IOS 15.2", "high", "Diego Martín"),
    ("A08", "dc-ot-01", "server", "OPS", "10.60.0.5", "Windows Server 2019", "high", "Diego Martín"),
    ("A09", "hist-01", "historian", "OPS", "10.60.0.10", "Windows Server 2019", "high", "Diego Martín"),
    ("A10", "mes-01", "server", "OPS", "10.60.0.20", "Windows Server 2019", "high", "Diego Martín"),
    ("A11", "ews-01", "engineering_ws", "OPS", "10.60.0.30", "Windows 10 LTSC", "high", "Diego Martín"),
    ("A12", "scada-l1", "scada", "SUP1", "10.70.1.10", "Windows Server 2019", "high", "Marta Ruiz"),
    ("A13", "hmi-l1-a", "hmi", "SUP1", "10.70.1.21", "Windows 10 IoT", "high", "Marta Ruiz"),
    ("A14", "hmi-l1-b", "hmi", "SUP1", "10.70.1.22", "Windows 7 Embedded", "high", "Marta Ruiz"),
    ("A15", "plc-l1-filler", "plc", "CTL1", "10.80.1.11", "Firmware 4.2", "high", "Marta Ruiz"),
    ("A16", "plc-l1-capper", "plc", "CTL1", "10.80.1.12", "Firmware 4.2", "high", "Marta Ruiz"),
    ("A17", "rio-l1", "remote_io", "CTL1", "10.80.1.40", "Firmware 2.1", "medium", "Marta Ruiz"),
    ("A18", "hmi-l2-a", "hmi", "SUP2", "10.70.2.21", "Windows 10 IoT", "high", "Pablo Ortega"),
    ("A19", "ews-l2", "engineering_ws", "SUP2", "10.70.2.30", "Windows 7", "medium", "Pablo Ortega"),
    ("A20", "plc-l2-labeller", "plc", "CTL2", "10.80.2.11", "Firmware 3.9", "high", "Pablo Ortega"),
    ("A21", "plc-l2-palletiser", "plc", "CTL2", "10.80.2.12", "Firmware 3.9", "high", "Pablo Ortega"),
    ("A22", "plc-l2-wrapper", "plc", "CTL2", "10.80.3.13", "Firmware 3.9", "medium", "Pablo Ortega"),
    ("A23", "sis-l2", "safety_plc", "CTL2", "10.80.2.50", "Firmware 1.8", "high", "Pablo Ortega"),
    ("A24", "sis-l1", "safety_plc", "SIS", "10.90.0.11", "Firmware 1.8", "high", ""),
    ("A25", "cam-qc-01", "camera", "", "10.70.1.60", "Firmware 5.0", "low", "Marta Ruiz"),
]

RULES = [  # rule_id, src_zone, dst_zone, src, dst, service, purpose, approved_by, expires
    ("R01", "ENT", "DMZ", "it-admin-05", "jump-01", "tcp/3389", "IT admins to the jump host", "Diego Martín", ""),
    ("R02", "ENT", "DMZ", "*", "hist-mirror", "tcp/443", "Production reports from the historian mirror", "Diego Martín", ""),
    ("R03", "OPS", "DMZ", "hist-01", "hist-mirror", "tcp/5450", "Historian replication", "Diego Martín", ""),
    ("R04", "DMZ", "OPS", "jump-01", "ews-01", "tcp/3389", "Engineering sessions from the jump host", "Diego Martín", ""),
    ("R05", "OPS", "DMZ", "*", "patch-01", "tcp/8443", "Patches and antivirus updates", "Diego Martín", ""),
    ("R06", "SUP1", "OPS", "scada-l1", "hist-01", "tcp/5450", "Line 1 data to the historian", "Marta Ruiz", ""),
    ("R07", "SUP2", "OPS", "hmi-l2-a", "hist-01", "tcp/5450", "Line 2 data to the historian", "Pablo Ortega", ""),
    ("R08", "OPS", "CTL1", "ews-01", "*", "tcp/102", "PLC programming for line 1", "Marta Ruiz", ""),
    ("R09", "SUP1", "CTL1", "scada-l1", "*", "tcp/502", "SCADA polling line 1", "Marta Ruiz", ""),
    ("R10", "SUP2", "CTL2", "hmi-l2-a", "*", "tcp/44818", "HMI to line 2 controllers", "Pablo Ortega", ""),
    ("R11", "ENT", "OPS", "*", "*", "any", "Legacy rule from commissioning", "", ""),
    ("R12", "Internet", "DMZ", "*", "jump-01", "tcp/443", "Vendor remote access portal", "Diego Martín", ""),
    ("R13", "DMZ", "SUP1", "jump-01", "*", "tcp/5900", "Vendor HMI upgrade (temporary)", "Marta Ruiz", "2026-09-30"),
    ("R14", "DMZ", "OPS", "jump-01", "sw-core-ot", "tcp/23", "Switch management", "Diego Martín", ""),
    ("R15", "SUP1", "OPS", "*", "*", "udp/514", "Syslog from line 1", "Marta Ruiz", ""),
    ("R16", "DMZ", "OPS", "jump-01", "mes-01", "tcp/3389", "MES upgrade by the vendor (temporary)", "Diego Martín", "2026-10-28"),
]

FLOWS = [  # src_ip, dst_ip, proto, port, count, last_seen
    ("10.10.3.5", "10.50.0.10", "tcp", 3389, 42, "2026-10-19"),
    ("10.10.4.21", "10.50.0.20", "tcp", 443, 310, "2026-10-19"),
    ("10.60.0.10", "10.50.0.20", "tcp", 5450, 8640, "2026-10-20"),
    ("10.50.0.10", "10.60.0.30", "tcp", 3389, 18, "2026-10-17"),
    ("10.60.0.20", "10.50.0.30", "tcp", 8443, 96, "2026-10-20"),
    ("10.60.0.30", "10.50.0.30", "tcp", 8443, 40, "2026-10-20"),
    ("10.70.1.10", "10.60.0.10", "tcp", 5450, 8640, "2026-10-20"),
    ("10.70.2.21", "10.60.0.10", "tcp", 5450, 8600, "2026-10-20"),
    ("10.60.0.30", "10.80.1.11", "tcp", 102, 12, "2026-10-14"),
    ("10.70.1.10", "10.80.1.11", "tcp", 502, 50000, "2026-10-20"),
    ("10.70.1.10", "10.80.1.12", "tcp", 502, 50000, "2026-10-20"),
    ("10.70.2.21", "10.80.2.11", "tcp", 44818, 40000, "2026-10-20"),
    ("10.70.2.21", "10.80.2.50", "tcp", 44818, 2000, "2026-10-20"),
    ("10.10.8.10", "10.60.0.20", "tcp", 1433, 2200, "2026-10-20"),
    ("203.0.113.45", "10.50.0.10", "tcp", 443, 30, "2026-10-16"),
    ("10.50.0.10", "10.70.1.21", "tcp", 5900, 6, "2026-10-12"),
    ("10.50.0.10", "10.60.0.2", "tcp", 23, 15, "2026-10-18"),
    ("10.50.0.10", "10.60.0.20", "tcp", 3389, 4, "2026-10-19"),
    ("10.10.4.21", "10.80.1.11", "tcp", 502, 3, "2026-10-09"),
    ("198.51.100.77", "10.70.1.22", "tcp", 3389, 9, "2026-10-15"),
    ("10.70.1.21", "192.0.2.80", "tcp", 443, 120, "2026-10-20"),
    ("10.70.1.250", "10.70.1.10", "tcp", 445, 40, "2026-10-18"),
    ("10.70.2.30", "10.80.2.12", "tcp", 44818, 25, "2026-10-13"),
]


def _write(path: Path, header: list[str], rows) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def write(folder: Path) -> None:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    _write(folder / "zones.csv", ["zone_id", "name", "level", "subnet", "sl_target", "owner"], ZONES)
    _write(folder / "assets.csv", ["asset_id", "name", "type", "zone", "ip", "os", "criticality", "owner"], ASSETS)
    _write(folder / "conduits.csv", ["rule_id", "src_zone", "dst_zone", "src", "dst", "service", "purpose", "approved_by", "expires"], RULES)
    _write(folder / "flows.csv", ["src_ip", "dst_ip", "proto", "port", "count", "last_seen"], FLOWS)
    (folder / "settings.json").write_text(json.dumps(SETTINGS, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
