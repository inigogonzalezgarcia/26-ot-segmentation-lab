# Data format

Five files in one folder. Column names are case-insensitive, commas or semicolons both work, and a UTF-8 BOM (Excel) is fine. Spanish headers are accepted for the most common columns (`zona`, `nombre`, `nivel`, `subred`, `responsable`, `tipo`, `criticidad`, `servicio`, `motivo`, `aprobado_por`, `caduca`, `puerto`).

## zones.csv (required)

| Column | Example | Notes |
|---|---|---|
| zone_id | `SUP1` | Short id used in the other files. |
| name | `Line 1 supervisory` | |
| level | `2` | Purdue level: `4`/`5` enterprise, `DMZ` (or `3.5`), `3` site operations, `2` supervisory, `1` control, `0` process. |
| subnet | `10.70.1.0/24` | Used to place flows from devices that are not in the inventory. |
| sl_target | `2` | Target security level (1–4), shown next to end-of-life systems. |
| owner | `Marta Ruiz` | The person who approves conduits into the zone. |

## assets.csv (required)

| Column | Example | Notes |
|---|---|---|
| asset_id | `A13` | |
| name | `hmi-l1-a` | Rules can name hosts by name, id or CIDR. |
| type | `hmi` | `plc`, `hmi`, `scada`, `engineering_ws`, `historian`, `jump_host`, `safety_plc`, `rtu`, `remote_io`, `switch`, `server`, `workstation`… A `jump_host` is the approved entry point for remote sessions; `safety_plc` (or `sis`) marks the safety system. |
| zone | `SUP1` | Empty means not assigned. |
| ip | `10.70.1.21` | |
| os | `Windows 10 IoT` | Firmware or OS; Windows XP/7/2000/2003/2008 are flagged as end of life. |
| criticality | `high` | `high`, `medium`, `low`. |
| owner | `Marta Ruiz` | |

## conduits.csv (approved firewall rules)

| Column | Example | Notes |
|---|---|---|
| rule_id | `R09` | |
| src_zone / dst_zone | `SUP1` / `CTL1` | Use `Internet` for anything outside the site. |
| src / dst | `scada-l1` / `*` | Host name, asset id, CIDR, or `*` for the whole zone. |
| service | `tcp/502` | `tcp/502`, `udp/161`, `502` (tcp) or `any`. |
| purpose | `SCADA polling line 1` | |
| approved_by | `Marta Ruiz` | Empty is flagged. |
| expires | `2026-09-30` | For temporary rules (vendor work, commissioning). |

## flows.csv (observed traffic)

An export from the OT firewall, NetFlow or a passive monitoring tool, ideally covering a full production cycle (a week with every shift and a changeover).

| Column | Example |
|---|---|
| src_ip | `10.70.1.10` |
| dst_ip | `10.80.1.11` |
| proto | `tcp` |
| port | `502` |
| count | `50000` (sessions or flow records) |
| last_seen | `2026-10-20` |

Flows inside one zone are only used to find devices missing from the inventory.

## settings.json (optional)

```json
{"organisation": "Fabrikam Foods", "site": "Guadalajara bottling plant", "as_of": "2026-10-20"}
```

## Rules of the model

- **IT to OT** only through the DMZ: enterprise (L4+) may talk to the DMZ, the DMZ to site operations (L3).
- **The DMZ stops at L3**: it does not reach supervisory or control zones directly.
- **Inside OT, one level at a time**: L3 to L2, L2 to L1. Skipping a level is flagged.
- **Controller protocols** (Modbus/TCP, S7comm, EtherNet/IP, DNP3, IEC 104, BACnet, PROFINET) stay inside the cell: L2 to L1 is fine, anything from L3 or above is critical.
- **Remote admin** (RDP, VNC, SSH, Telnet, TeamViewer) into OT starts on the jump host.
- **The safety system** has its own zone and is not writable from other systems.
