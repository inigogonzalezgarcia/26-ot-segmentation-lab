import csv
import tempfile
import unittest
from datetime import date
from pathlib import Path

from otseg import checks, cli, model
from otseg.checks import CRITICAL, INFO, WARNING, Config, path_issue, run_all
from otseg.model import Asset, Flow, Rule, Site, Zone

T = date(2026, 10, 20)
ZONES = [Zone("ENT", "Enterprise IT", 4, "10.10.0.0/16", 1, "Ana"), Zone("DMZ", "DMZ", 3.5, "10.50.0.0/24", 3, "Ana"),
         Zone("OPS", "Operations", 3, "10.60.0.0/24", 2, "Ana"), Zone("SUP", "Supervisory", 2, "10.70.0.0/24", 2, "Ana"),
         Zone("CTL", "Control", 1, "10.80.0.0/24", 3, "Ana")]
ASSETS = [Asset("A1", "pc", "workstation", "ENT", "10.10.0.5", "Windows 11", "low", "Ana"),
          Asset("A2", "jump", "jump_host", "DMZ", "10.50.0.10", "Windows Server 2022", "high", "Ana"),
          Asset("A3", "hist", "historian", "OPS", "10.60.0.10", "Windows Server 2022", "high", "Ana"),
          Asset("A4", "scada", "scada", "SUP", "10.70.0.10", "Windows Server 2022", "high", "Ana"),
          Asset("A5", "plc", "plc", "CTL", "10.80.0.11", "Firmware 1", "high", "Ana")]


def site(rules=(), flows=(), assets=None, zones=None):
    return Site(zones=list(zones or ZONES), assets=list(ASSETS if assets is None else assets), rules=list(rules),
                flows=list(flows), organisation="Test", site="Plant", as_of=T)


def rule(rid, sz, dz, src="*", dst="*", port=502, **kw):
    return Rule(rid, sz, dz, src, dst, "tcp" if port else "any", port, "purpose", kw.pop("approved_by", "Ana"), **kw)


def flow(src, dst, port=502, count=10):
    return Flow(src, dst, "tcp", port, count)


def codes(s, c=None):
    return [f.code for f in run_all(s, c)[0]]


class ParsingTests(unittest.TestCase):
    def test_levels_services_and_dates(self):
        self.assertEqual(model.parse_level("DMZ"), 3.5)
        self.assertEqual(model.parse_level("L2"), 2.0)
        self.assertEqual(model.parse_service("udp/161"), ("udp", 161))
        self.assertEqual(model.parse_service("502"), ("tcp", 502))
        self.assertEqual(model.parse_service("any"), ("any", None))
        self.assertEqual(model.parse_date("30/09/2026"), date(2026, 9, 30))
        self.assertEqual(model.service_name(102), "S7comm")

    def test_semicolon_csv_with_bom_and_spanish_headers(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "zones.csv").write_text("﻿zona;nombre;nivel;subred;sl_target;responsable\nZ1;Planta;L2;10.1.0.0/24;2;Ana\n", encoding="utf-8")
            (p / "assets.csv").write_text("id;nombre;tipo;zona;ip;os;criticidad;responsable\nA1;hmi;HMI;Z1;10.1.0.5;Windows 10;alta;Ana\n",
                                          encoding="utf-8")
            s = model.load(p, T)
            self.assertEqual((s.zones[0].level, s.assets[0].type, s.assets[0].zone), (2.0, "hmi", "Z1"))
            self.assertEqual(s.zone_of_ip("10.1.0.99").id, "Z1")


class ModelTests(unittest.TestCase):
    def test_path_rules(self):
        z = {x.id: x for x in ZONES}
        self.assertEqual(path_issue(z["ENT"], z["DMZ"]), "")
        self.assertEqual(path_issue(z["DMZ"], z["OPS"]), "")
        self.assertEqual(path_issue(z["SUP"], z["CTL"]), "")
        self.assertIn("bypassing the IT/OT DMZ", path_issue(z["ENT"], z["OPS"]))
        self.assertIn("DMZ should only reach", path_issue(z["DMZ"], z["SUP"]))
        self.assertIn("skipping a level", path_issue(z["OPS"], z["CTL"]))

    def test_clean_site_has_no_findings(self):
        rules = [rule("R1", "ENT", "DMZ", "pc", "jump", 3389), rule("R2", "OPS", "DMZ", "hist", "*", 5450),
                 rule("R3", "SUP", "OPS", "scada", "hist", 5450), rule("R4", "SUP", "CTL", "scada", "plc", 502)]
        flows = [flow("10.10.0.5", "10.50.0.10", 3389), flow("10.60.0.10", "10.50.0.10", 5450),
                 flow("10.70.0.10", "10.60.0.10", 5450), flow("10.70.0.10", "10.80.0.11", 502), flow("10.80.0.11", "10.80.0.11", 502)]
        findings, rows = run_all(site(rules, flows))
        self.assertEqual(findings, [])
        self.assertTrue(all(p["action"] == "allow" for p in checks.proposal(site(rules, flows), rows)))


class ConduitTests(unittest.TestCase):
    def test_any_service_any_host_and_path(self):
        c = codes(site([rule("R1", "ENT", "OPS", port=None, approved_by="")]))
        for code in ("RULE_ANY_SERVICE", "RULE_PATH", "RULE_NO_APPROVAL", "RULE_UNUSED"):
            self.assertIn(code, c)
        self.assertIn("RULE_ANY_HOST", codes(site([rule("R2", "SUP", "CTL")])))

    def test_expired_and_expiring(self):
        s = site([rule("R1", "SUP", "CTL", "scada", "plc", expires=date(2026, 10, 1)),
                  rule("R2", "SUP", "CTL", "scada", "plc", expires=date(2026, 10, 30)),
                  rule("R3", "SUP", "CTL", "scada", "plc", expires=date(2026, 11, 30))])
        f = {(x.code, x.ref): x.severity for x in run_all(s)[0]}
        self.assertEqual(f[("RULE_EXPIRED", "R1")], WARNING)
        self.assertEqual(f[("RULE_EXPIRING", "R2")], INFO)
        self.assertNotIn(("RULE_EXPIRING", "R3"), f)

    def test_unknown_zone_and_unused_switch(self):
        s = site([rule("R1", "SUP", "NOPE", "scada", "plc")])
        self.assertIn("RULE_UNKNOWN_ZONE", codes(s))
        self.assertNotIn("RULE_UNUSED", codes(s, Config(unused_rules=False)))


class TrafficTests(unittest.TestCase):
    def test_flow_without_conduit_and_it_to_plc(self):
        c = codes(site([], [flow("10.10.0.5", "10.80.0.11", 502)]))
        self.assertIn("NO_CONDUIT", c)
        self.assertIn("INDUSTRIAL_PROTOCOL", c)

    def test_allowed_flow_that_breaks_the_model(self):
        s = site([rule("R1", "ENT", "OPS", port=None)], [flow("10.10.0.5", "10.60.0.10", 1433)])
        f = [x for x in run_all(s)[0] if x.code == "PATH_VIOLATION"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].ref, "R1")

    def test_internet_cleartext_and_unknown_host(self):
        s = site([rule("R1", "DMZ", "OPS", "jump", "hist", 23)],
                 [flow("10.70.0.10", "192.0.2.1", 443), flow("10.50.0.10", "10.60.0.10", 23), flow("10.80.0.99", "10.80.0.11", 502)])
        c = codes(s)
        self.assertIn("OT_TO_INTERNET", c)
        self.assertNotIn("NO_CONDUIT", c)  # the internet finding already says it
        self.assertIn("CLEARTEXT_PROTOCOL", c)
        unk = [x for x in run_all(s)[0] if x.code == "UNKNOWN_HOST"]
        self.assertEqual((len(unk), unk[0].severity), (1, CRITICAL))

    def test_remote_access_must_use_the_jump_host(self):
        c = codes(site([], [flow("198.51.100.7", "10.70.0.10", 3389)]))
        self.assertIn("REMOTE_NOT_VIA_JUMP", c)
        ok = site([rule("R1", "DMZ", "OPS", "jump", "hist", 3389)], [flow("10.50.0.10", "10.60.0.10", 3389)])
        self.assertEqual(codes(ok), [])

    def test_proposal_actions(self):
        s = site([rule("R1", "SUP", "CTL", "scada", "plc", 502)],
                 [flow("10.70.0.10", "10.80.0.11", 502), flow("10.10.0.5", "10.80.0.11", 502), flow("10.10.0.5", "10.60.0.10", 1433),
                  flow("10.70.0.10", "10.80.0.11", 23)])
        acts = {(p["src"], p["service"]): p["action"] for p in checks.proposal(s, run_all(s)[1])}
        self.assertEqual(acts[("scada (10.70.0.10)", "tcp/502")], "allow")
        self.assertEqual(acts[("pc (10.10.0.5)", "tcp/502")], "block")
        self.assertEqual(acts[("pc (10.10.0.5)", "tcp/1433")], "re-route via DMZ")
        self.assertEqual(acts[("scada (10.70.0.10)", "tcp/23")], "review")


class AssetTests(unittest.TestCase):
    def test_zone_subnet_eol_and_owner(self):
        assets = ASSETS + [Asset("A6", "cam", "camera", "", "10.70.0.60"), Asset("A7", "hmi-old", "hmi", "SUP", "10.71.0.5", "Windows 7", "high"),
                           Asset("A8", "ews-old", "engineering_ws", "OPS", "10.60.0.30", "Windows XP", "medium", "Ana")]
        f = {(x.code, x.ref): x.severity for x in run_all(site(assets=assets))[0]}
        self.assertEqual(f[("NO_ZONE", "A6")], CRITICAL)
        self.assertEqual(f[("WRONG_SUBNET", "A7")], WARNING)
        self.assertEqual(f[("END_OF_LIFE_OS", "A7")], CRITICAL)
        self.assertEqual(f[("END_OF_LIFE_OS", "A8")], WARNING)
        self.assertEqual(f[("NO_OWNER", "A7")], INFO)

    def test_safety_system(self):
        assets = ASSETS + [Asset("A9", "sis", "safety_plc", "CTL", "10.80.0.50", "Firmware 1", "high", "Ana")]
        s = site([rule("R1", "SUP", "CTL", "scada", "*", 502)], [flow("10.70.0.10", "10.80.0.50", 502)], assets=assets)
        c = codes(s)
        self.assertIn("SIS_SHARED_ZONE", c)
        self.assertIn("SIS_REACHABLE", c)


class DemoTests(unittest.TestCase):
    def test_demo_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            data, out = Path(d) / "data", Path(d) / "out"
            self.assertEqual(cli.main(["demo", "--data", str(data), "--out", str(out)]), 0)
            for name in ("report.html", "review.md", "findings.csv", "actions.csv", "firewall-proposal.csv", "zone-matrix.csv"):
                self.assertTrue((out / name).exists(), name)
            with open(out / "findings.csv", encoding="utf-8") as fh:
                found = {r["code"] for r in csv.DictReader(fh)}
            expected = {"RULE_ANY_SERVICE", "RULE_ANY_HOST", "RULE_PATH", "RULE_EXPIRED", "RULE_EXPIRING", "RULE_NO_APPROVAL", "RULE_UNUSED",
                        "NO_CONDUIT", "PATH_VIOLATION", "INDUSTRIAL_PROTOCOL", "CLEARTEXT_PROTOCOL", "OT_TO_INTERNET",
                        "REMOTE_NOT_VIA_JUMP", "SIS_REACHABLE", "UNKNOWN_HOST", "NO_ZONE", "WRONG_SUBNET", "END_OF_LIFE_OS",
                        "SIS_SHARED_ZONE", "NO_OWNER", "ZONE_NO_OWNER"}
            self.assertEqual(expected - found, set())
            html = (out / "report.html").read_text(encoding="utf-8")
            self.assertIn("<svg", html)
            self.assertIn("Proposed conduits", html)

    def test_missing_files(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(cli.main(["report", d, "--out", str(Path(d) / "o")]), 2)


if __name__ == "__main__":
    unittest.main()
