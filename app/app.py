import csv
import io
import ipaddress
import json
import logging
import os
import socket
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import paramiko
import winrm

import requests
import urllib3
from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

FORTIGATE_URL = os.getenv(
    "FORTIGATE_URL",
    "https://192.168.2.1",
).rstrip("/")

FORTI_TOKEN_FILE = Path(
    os.getenv(
        "TOKEN_FILE",
        "/run/secrets/fortitoken",
    )
)

UNIFI_URL = os.getenv(
    "UNIFI_URL",
    "https://192.168.2.3",
).rstrip("/")

UNIFI_SITE_ID = os.getenv(
    "UNIFI_SITE_ID",
    "88f7af54-98f8-306a-a1c7-c9349722b1f6",
)

UNIFI_API_KEY_FILE = Path(
    os.getenv(
        "UNIFI_API_KEY_FILE",
        "/run/secrets/unifi-api.key",
    )
)

DB_PATH = Path(
    os.getenv(
        "DB_PATH",
        "/data/inventory.db",
    )
)

CHANGE_FILE = Path(
    os.getenv(
        "CHANGE_FILE",
        "/data/fortigate-changes.cli",
    )
)

VERIFY_TLS = os.getenv(
    "VERIFY_TLS",
    "false",
).lower() == "true"

DHCP_SERVER_ID = int(
    os.getenv(
        "DHCP_SERVER_ID",
        "3",
    )
)

LIN_USERS_FILE = Path(os.getenv("LIN_USERS_FILE", "/run/secrets/lin-users.key"))
LIN_PASSWORDS_FILE = Path(os.getenv("LIN_PASSWORDS_FILE", "/run/secrets/lin-passwords.key"))
WIN_USERS_FILE = Path(os.getenv("WIN_USERS_FILE", "/run/secrets/win-users.key"))
WIN_PASSWORDS_FILE = Path(os.getenv("WIN_PASSWORDS_FILE", "/run/secrets/win-passwords.key"))
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
SSH_TIMEOUT = int(os.getenv("SSH_TIMEOUT", "6"))
WINRM_HTTP_PORT = int(os.getenv("WINRM_HTTP_PORT", "5985"))
WINRM_HTTPS_PORT = int(os.getenv("WINRM_HTTPS_PORT", "5986"))
WINRM_TIMEOUT = int(os.getenv("WINRM_TIMEOUT", "20"))
WINRM_VERIFY_TLS = os.getenv("WINRM_VERIFY_TLS", "false").lower() == "true"

app = FastAPI(title="Inventory")
templates = Jinja2Templates(directory="templates")

SSH_SCAN_CATEGORIES = {
    "Server",
    "Desktop",
    "Laptop",
    "VM",
    "Printer",
    "Unknown",
}

CATEGORIES = [
    "Unknown",
    "Infrastructure",
    "Firewall",
    "Switch",
    "Access Point",
    "Camera",
    "Server",
    "Docker",
    "Proxmox",
    "Storage",
    "VM",
    "Desktop",
    "Laptop",
    "Printer",
    "Phone",
    "Tablet",
    "Raspberry Pi",
    "ESP32",
    "Meshtastic",
    "IoT",
    "Appliance",
]

SORT_COLUMNS = {
    "current_ip": "m.current_ip",
    "ip_source": "m.ip_source",
    "reserved_ip": "m.reserved_ip",
    "mac": "m.mac",
    "hostname": "m.hostname",
    "unifi_name": "m.unifi_name",
    "connection": "m.unifi_connection_type",
    "uplink": "m.unifi_uplink_name",
    "unifi_model": "m.unifi_model",
    "unifi_firmware": "m.unifi_firmware",
    "unifi_state": "m.unifi_state",
    "vendor": "m.vendor",
    "type": "m.type",
    "family": "m.family",
    "os": "m.os",
    "hardware_version": "m.hardware_version",
    "software_version": "m.software_version",
    "logical_name": "d.logical_name",
    "category": "d.category",
    "location": "d.location",
    "notes": "d.notes",
    "proposed_ip": "m.proposed_ip",
    "reservation_description": "m.reservation_description",
}


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.create_function(
        "IP_SORT",
        1,
        lambda value: int(ipaddress.ip_address(value))
        if value
        else None,
    )

    return conn


def ensure_column(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    columns = {
        row[1]
        for row in conn.execute(
            f"PRAGMA table_info({table})"
        )
    }

    if column not in columns:
        conn.execute(
            f"""
            ALTER TABLE {table}
            ADD COLUMN {column} {definition}
            """
        )


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                logical_name TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT 'Unknown',
                location TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS device_macs (
                mac TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                current_ip TEXT NOT NULL DEFAULT '',
                ip_source TEXT NOT NULL DEFAULT '',
                hostname TEXT NOT NULL DEFAULT '',
                vendor TEXT NOT NULL DEFAULT '',
                type TEXT NOT NULL DEFAULT '',
                family TEXT NOT NULL DEFAULT '',
                os TEXT NOT NULL DEFAULT '',
                hardware_version TEXT NOT NULL DEFAULT '',
                software_version TEXT NOT NULL DEFAULT '',
                reserved INTEGER NOT NULL DEFAULT 0,
                reserved_ip TEXT NOT NULL DEFAULT '',
                reservation_description TEXT NOT NULL DEFAULT '',
                reservation_id INTEGER NOT NULL DEFAULT 0,
                proposed_ip TEXT NOT NULL DEFAULT '',
                proposed_description TEXT NOT NULL DEFAULT '',
                unifi_name TEXT NOT NULL DEFAULT '',
                unifi_connection_type TEXT NOT NULL DEFAULT '',
                unifi_uplink_id TEXT NOT NULL DEFAULT '',
                unifi_uplink_name TEXT NOT NULL DEFAULT '',
                unifi_model TEXT NOT NULL DEFAULT '',
                unifi_firmware TEXT NOT NULL DEFAULT '',
                unifi_state TEXT NOT NULL DEFAULT '',
                unifi_managed INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(device_id)
                    REFERENCES devices(device_id)
            );

            CREATE TABLE IF NOT EXISTS host_credentials (
                device_id TEXT PRIMARY KEY,
                user_key TEXT NOT NULL DEFAULT '',
                password_key TEXT NOT NULL DEFAULT '',
                last_success TEXT NOT NULL DEFAULT '',
                last_failure TEXT NOT NULL DEFAULT '',
                last_error TEXT NOT NULL DEFAULT '',
                scan_method TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(device_id) REFERENCES devices(device_id)
            );

            CREATE TABLE IF NOT EXISTS system_facts (
                device_id TEXT PRIMARY KEY,
                scan_ip TEXT NOT NULL DEFAULT '',
                hostname TEXT NOT NULL DEFAULT '',
                os_name TEXT NOT NULL DEFAULT '',
                os_version TEXT NOT NULL DEFAULT '',
                kernel TEXT NOT NULL DEFAULT '',
                cpu_model TEXT NOT NULL DEFAULT '',
                cpu_sockets INTEGER NOT NULL DEFAULT 0,
                cpu_cores INTEGER NOT NULL DEFAULT 0,
                cpu_threads INTEGER NOT NULL DEFAULT 0,
                gpu_summary TEXT NOT NULL DEFAULT '',
                memory_total INTEGER NOT NULL DEFAULT 0,
                uptime_seconds INTEGER NOT NULL DEFAULT 0,
                interfaces_json TEXT NOT NULL DEFAULT '[]',
                disks_json TEXT NOT NULL DEFAULT '[]',
                docker_json TEXT NOT NULL DEFAULT '{}',
                scanned_at TEXT NOT NULL DEFAULT '',
                scan_status TEXT NOT NULL DEFAULT '',
                scan_error TEXT NOT NULL DEFAULT '',
                scan_method TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(device_id) REFERENCES devices(device_id)
            );

            CREATE TABLE IF NOT EXISTS system_interfaces (
                interface_id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                ifname TEXT NOT NULL DEFAULT '',
                mac TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT '',
                mtu INTEGER NOT NULL DEFAULT 0,
                link_type TEXT NOT NULL DEFAULT '',
                addresses_json TEXT NOT NULL DEFAULT '[]',
                UNIQUE(device_id, ifname),
                FOREIGN KEY(device_id) REFERENCES devices(device_id)
            );

            CREATE TABLE IF NOT EXISTS system_disks (
                disk_id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                parent_name TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL DEFAULT '',
                device_type TEXT NOT NULL DEFAULT '',
                model TEXT NOT NULL DEFAULT '',
                serial TEXT NOT NULL DEFAULT '',
                mountpoint TEXT NOT NULL DEFAULT '',
                filesystem TEXT NOT NULL DEFAULT '',
                size_bytes INTEGER NOT NULL DEFAULT 0,
                used_bytes INTEGER NOT NULL DEFAULT 0,
                free_bytes INTEGER NOT NULL DEFAULT 0,
                UNIQUE(device_id, name, mountpoint),
                FOREIGN KEY(device_id) REFERENCES devices(device_id)
            );

            CREATE TABLE IF NOT EXISTS docker_containers (
                container_key INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT '',
                network_mode TEXT NOT NULL DEFAULT '',
                ip_address TEXT NOT NULL DEFAULT '',
                ports TEXT NOT NULL DEFAULT '',
                image TEXT NOT NULL DEFAULT '',
                size_rw INTEGER NOT NULL DEFAULT 0,
                size_rootfs INTEGER NOT NULL DEFAULT 0,
                cpu_percent TEXT NOT NULL DEFAULT '',
                memory_usage TEXT NOT NULL DEFAULT '',
                memory_percent TEXT NOT NULL DEFAULT '',
                gpu_summary TEXT NOT NULL DEFAULT '',
                UNIQUE(device_id, name),
                FOREIGN KEY(device_id) REFERENCES devices(device_id)
            );

            CREATE TABLE IF NOT EXISTS app_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            );
            """
        )

        migrations = {
            "reservation_id":
                "INTEGER NOT NULL DEFAULT 0",
            "proposed_ip":
                "TEXT NOT NULL DEFAULT ''",
            "proposed_description":
                "TEXT NOT NULL DEFAULT ''",
            "ip_source":
                "TEXT NOT NULL DEFAULT ''",
            "unifi_name":
                "TEXT NOT NULL DEFAULT ''",
            "unifi_connection_type":
                "TEXT NOT NULL DEFAULT ''",
            "unifi_uplink_id":
                "TEXT NOT NULL DEFAULT ''",
            "unifi_uplink_name":
                "TEXT NOT NULL DEFAULT ''",
            "unifi_model":
                "TEXT NOT NULL DEFAULT ''",
            "unifi_firmware":
                "TEXT NOT NULL DEFAULT ''",
            "unifi_state":
                "TEXT NOT NULL DEFAULT ''",
            "unifi_managed":
                "INTEGER NOT NULL DEFAULT 0",
        }

        for column, definition in migrations.items():
            ensure_column(
                conn,
                "device_macs",
                column,
                definition,
            )

        system_migrations = {
            "gpu_summary": "TEXT NOT NULL DEFAULT ''",
            "scan_method": "TEXT NOT NULL DEFAULT ''",
        }
        for column, definition in system_migrations.items():
            ensure_column(conn, "system_facts", column, definition)
        ensure_column(conn, "host_credentials", "scan_method", "TEXT NOT NULL DEFAULT ''")

        docker_migrations = {
            "cpu_percent": "TEXT NOT NULL DEFAULT ''",
            "memory_usage": "TEXT NOT NULL DEFAULT ''",
            "memory_percent": "TEXT NOT NULL DEFAULT ''",
            "gpu_summary": "TEXT NOT NULL DEFAULT ''",
        }
        for column, definition in docker_migrations.items():
            ensure_column(conn, "docker_containers", column, definition)

        schema_row = conn.execute(
            "SELECT value FROM app_metadata WHERE key='systems_schema_version'"
        ).fetchone()
        schema_version = schema_row[0] if schema_row else ''
        if schema_version != '2':
            conn.execute("DELETE FROM system_interfaces")
            conn.execute("DELETE FROM system_disks")
            conn.execute("DELETE FROM docker_containers")
            conn.execute("DELETE FROM system_facts")
            conn.execute(
                """
                INSERT INTO app_metadata(key,value) VALUES('systems_schema_version','2')
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """
            )


@app.on_event("startup")
def startup() -> None:
    init_db()


def read_secret(path: Path) -> str:
    return path.read_text(
        encoding="utf-8",
    ).strip()


def fg_get(path: str) -> dict[str, Any]:
    response = requests.get(
        f"{FORTIGATE_URL}{path}",
        headers={
            "Authorization":
                f"Bearer {read_secret(FORTI_TOKEN_FILE)}",
        },
        verify=VERIFY_TLS,
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


def unifi_get(path: str) -> dict[str, Any]:
    response = requests.get(
        f"{UNIFI_URL}{path}",
        headers={
            "X-API-Key":
                read_secret(UNIFI_API_KEY_FILE),
        },
        verify=VERIFY_TLS,
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


def pick(
    item: dict[str, Any],
    *keys: str,
) -> str:
    for key in keys:
        value = item.get(key)

        if value not in (
            None,
            "",
        ):
            return str(value)

    return ""


def normalize_items(
    data: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if not data:
        return []

    results = data.get(
        "results",
        [],
    )

    if isinstance(results, list):
        return [
            item
            for item in results
            if isinstance(item, dict)
        ]

    if isinstance(results, dict):
        for key in (
            "entries",
            "devices",
            "leases",
            "data",
        ):
            value = results.get(key)

            if isinstance(value, list):
                return [
                    item
                    for item in value
                    if isinstance(item, dict)
                ]

    return []


def try_monitor(
    paths: list[str],
) -> dict[str, Any] | None:
    for path in paths:
        try:
            data = fg_get(path)

            if (
                data.get("status") == "success"
                or data.get("results") is not None
            ):
                return data

        except Exception:
            continue

    return None


def extract_reservations() -> dict[str, dict[str, Any]]:
    data = fg_get(
        "/api/v2/cmdb/system.dhcp/server"
    )

    out: dict[str, dict[str, Any]] = {}

    for server in data.get(
        "results",
        [],
    ):
        if server.get("interface") != "internal":
            continue

        for item in server.get(
            "reserved-address",
            [],
        ):
            mac = str(
                item.get(
                    "mac",
                    "",
                )
            ).lower()

            if not mac:
                continue

            out[mac] = {
                "id": int(
                    item.get(
                        "id",
                        0,
                    )
                    or 0
                ),
                "ip": str(
                    item.get(
                        "ip",
                        "",
                    )
                ),
                "description": str(
                    item.get(
                        "description",
                        "",
                    )
                ),
            }

    return out


def fetch_unifi(
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    base = (
        "/proxy/network/integration/v1/sites/"
        f"{UNIFI_SITE_ID}"
    )

    devices = unifi_get(
        f"{base}/devices?limit=200"
    ).get(
        "data",
        [],
    )

    clients = unifi_get(
        f"{base}/clients?limit=200"
    ).get(
        "data",
        [],
    )

    return (
        [
            item
            for item in devices
            if isinstance(item, dict)
        ],
        [
            item
            for item in clients
            if isinstance(item, dict)
        ],
    )


def ensure_device(
    conn: sqlite3.Connection,
    mac: str,
) -> str:
    existing = conn.execute(
        """
        SELECT device_id
        FROM device_macs
        WHERE mac=?
        """,
        (mac,),
    ).fetchone()

    if existing:
        return existing["device_id"]

    device_id = str(
        uuid.uuid4()
    )

    conn.execute(
        """
        INSERT INTO devices(
            device_id
        )
        VALUES (?)
        """,
        (device_id,),
    )

    return device_id


def auto_categorize_unknown_devices(
    conn: sqlite3.Connection,
) -> int:
    """Assign only high-confidence categories and never overwrite manual values."""
    rules = [
        ("Firewall", "fortigate|fortinet"),
        ("Access Point", "access point|wireless ap|u6-|u7-|uap-|unifi ap"),
        ("Switch", "switch|usw-|pro max 24|pro 24|poe-24"),
        ("Camera", "camera|g3 flex|g4 |g5 |protect"),
        ("Printer", "printer|laserjet|officejet|brother|epson|canon pixma"),
        ("Raspberry Pi", "raspberry pi|raspberrypi"),
        ("Proxmox", "proxmox|pmox"),
        ("Docker", "docker"),
        ("Storage", "storage|nas|synology|qnap|truenas"),
        ("Meshtastic", "meshtastic|heltec|sensecap|wio tracker"),
        ("ESP32", "esp32"),
    ]

    updated = 0
    for category, patterns in rules:
        terms = patterns.split("|")
        conditions = []
        values: list[Any] = [category]
        for term in terms:
            like = f"%{term.lower()}%"
            conditions.append(
                "("
                "LOWER(COALESCE(m.hostname, '')) LIKE ? OR "
                "LOWER(COALESCE(m.vendor, '')) LIKE ? OR "
                "LOWER(COALESCE(m.type, '')) LIKE ? OR "
                "LOWER(COALESCE(m.family, '')) LIKE ? OR "
                "LOWER(COALESCE(m.os, '')) LIKE ? OR "
                "LOWER(COALESCE(m.unifi_name, '')) LIKE ? OR "
                "LOWER(COALESCE(m.unifi_model, '')) LIKE ? OR "
                "LOWER(COALESCE(d.logical_name, '')) LIKE ?"
                ")"
            )
            values.extend([like] * 8)

        sql = f"""
            UPDATE devices AS d
            SET category=?
            WHERE d.category='Unknown'
              AND EXISTS (
                  SELECT 1
                  FROM device_macs AS m
                  WHERE m.device_id=d.device_id
                    AND ({' OR '.join(conditions)})
              )
        """
        cursor = conn.execute(sql, values)
        updated += cursor.rowcount

    return updated


def refresh_inventory() -> tuple[int, str]:
    reservations = extract_reservations()

    lease_data = try_monitor(
        [
            "/api/v2/monitor/system/dhcp",
            "/api/v2/monitor/system/dhcp/lease",
            "/api/v2/monitor/system/dhcp/select",
        ]
    )

    device_data = try_monitor(
        [
            "/api/v2/monitor/user/device",
            "/api/v2/monitor/user/device/select",
            "/api/v2/monitor/user/detected-device",
        ]
    )

    leases = normalize_items(
        lease_data
    )

    fg_devices = normalize_items(
        device_data
    )

    unifi_devices, unifi_clients = fetch_unifi()

    by_mac: dict[
        str,
        dict[str, Any],
    ] = {}

    for item in fg_devices:
        mac = pick(
            item,
            "mac",
            "mac_address",
            "mac-address",
        ).lower()

        if not mac:
            continue

        row = by_mac.setdefault(
            mac,
            {},
        )

        row.update(
            {
                "current_ip": pick(
                    item,
                    "ip",
                    "ipv4",
                    "ip_address",
                    "ip-address",
                ),
                "ip_source": "fortigate",
                "hostname": pick(
                    item,
                    "hostname",
                    "host",
                    "name",
                ),
                "vendor": pick(
                    item,
                    "vendor",
                    "hardware_vendor",
                    "hardware-vendor",
                ),
                "type": pick(
                    item,
                    "type",
                    "device_type",
                    "device-type",
                ),
                "family": pick(
                    item,
                    "family",
                ),
                "os": pick(
                    item,
                    "os",
                    "operating_system",
                ),
                "hardware_version": pick(
                    item,
                    "hardware_version",
                    "hardware-version",
                ),
                "software_version": pick(
                    item,
                    "software_version",
                    "software-version",
                ),
            }
        )

    for item in leases:
        mac = pick(
            item,
            "mac",
            "mac_address",
            "mac-address",
        ).lower()

        if not mac:
            continue

        row = by_mac.setdefault(
            mac,
            {},
        )

        ip = pick(
            item,
            "ip",
            "ipv4",
            "ip_address",
            "ip-address",
        )

        if ip:
            row["current_ip"] = ip
            row["ip_source"] = "dhcp"

        hostname = pick(
            item,
            "hostname",
            "host",
            "name",
        )

        if hostname:
            row["hostname"] = hostname

    managed_by_id: dict[
        str,
        str,
    ] = {}

    for item in unifi_devices:
        mac = str(
            item.get(
                "macAddress",
                "",
            )
        ).lower()

        if not mac:
            continue

        unifi_device_id = str(
            item.get(
                "id",
                "",
            )
        )

        name = str(
            item.get(
                "name",
                "",
            )
        )

        model = str(
            item.get(
                "model",
                "",
            )
        )

        if unifi_device_id:
            managed_by_id[
                unifi_device_id
            ] = (
                name
                or model
            )

        row = by_mac.setdefault(
            mac,
            {},
        )

        ip = str(
            item.get(
                "ipAddress",
                "",
            )
        )

        if ip:
            row["current_ip"] = ip
            row["ip_source"] = "unifi-device"

        row.update(
            {
                "unifi_name":
                    name,
                "unifi_model":
                    model,
                "unifi_firmware":
                    str(
                        item.get(
                            "firmwareVersion",
                            "",
                        )
                    ),
                "unifi_state":
                    str(
                        item.get(
                            "state",
                            "",
                        )
                    ),
                "unifi_managed":
                    1,
            }
        )

        if (
            not row.get("hostname")
            and name
        ):
            row["hostname"] = name

    for item in unifi_clients:
        mac = str(
            item.get(
                "macAddress",
                "",
            )
        ).lower()

        if not mac:
            continue

        row = by_mac.setdefault(
            mac,
            {},
        )

        ip = str(
            item.get(
                "ipAddress",
                "",
            )
        )

        if ip:
            row["current_ip"] = ip
            row["ip_source"] = "unifi-client"

        name = str(
            item.get(
                "name",
                "",
            )
        )

        uplink_id = str(
            item.get(
                "uplinkDeviceId",
                "",
            )
        )

        row.update(
            {
                "unifi_name":
                    name,
                "unifi_connection_type":
                    str(
                        item.get(
                            "type",
                            "",
                        )
                    ),
                "unifi_uplink_id":
                    uplink_id,
                "unifi_uplink_name":
                    managed_by_id.get(
                        uplink_id,
                        "",
                    ),
            }
        )

        if (
            name
            and (
                not row.get("hostname")
                or row.get("hostname") == mac
            )
        ):
            row["hostname"] = name

    for mac, reservation in reservations.items():
        row = by_mac.setdefault(
            mac,
            {},
        )

        if not row.get("current_ip"):
            row["current_ip"] = reservation.get(
                "ip",
                "",
            )
            row["ip_source"] = "reservation"

    now = datetime.now(
        timezone.utc
    ).isoformat()

    with db() as conn:
        # Reservation fields are a FortiGate-derived snapshot. Clear only
        # those fields first, then repopulate reservations that still exist.
        # Manual device metadata and proposed values are preserved.
        conn.execute(
            """
            UPDATE device_macs
            SET
                reserved = 0,
                reserved_ip = '',
                reservation_description = '',
                reservation_id = 0
            """
        )

        for mac, details in by_mac.items():
            device_id = ensure_device(
                conn,
                mac,
            )

            reservation = reservations.get(
                mac,
                {},
            )

            conn.execute(
                """
                INSERT INTO device_macs (
                    mac,
                    device_id,
                    current_ip,
                    ip_source,
                    hostname,
                    vendor,
                    type,
                    family,
                    os,
                    hardware_version,
                    software_version,
                    reserved,
                    reserved_ip,
                    reservation_description,
                    reservation_id,
                    unifi_name,
                    unifi_connection_type,
                    unifi_uplink_id,
                    unifi_uplink_name,
                    unifi_model,
                    unifi_firmware,
                    unifi_state,
                    unifi_managed,
                    last_seen
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT(mac) DO UPDATE SET
                    current_ip=excluded.current_ip,
                    ip_source=excluded.ip_source,
                    hostname=excluded.hostname,
                    vendor=excluded.vendor,
                    type=excluded.type,
                    family=excluded.family,
                    os=excluded.os,
                    hardware_version=excluded.hardware_version,
                    software_version=excluded.software_version,
                    reserved=excluded.reserved,
                    reserved_ip=excluded.reserved_ip,
                    reservation_description=
                        excluded.reservation_description,
                    reservation_id=excluded.reservation_id,
                    unifi_name=excluded.unifi_name,
                    unifi_connection_type=
                        excluded.unifi_connection_type,
                    unifi_uplink_id=
                        excluded.unifi_uplink_id,
                    unifi_uplink_name=
                        excluded.unifi_uplink_name,
                    unifi_model=excluded.unifi_model,
                    unifi_firmware=excluded.unifi_firmware,
                    unifi_state=excluded.unifi_state,
                    unifi_managed=excluded.unifi_managed,
                    last_seen=excluded.last_seen
                """,
                (
                    mac,
                    device_id,
                    str(details.get("current_ip", "")),
                    str(details.get("ip_source", "")),
                    str(details.get("hostname", "")),
                    str(details.get("vendor", "")),
                    str(details.get("type", "")),
                    str(details.get("family", "")),
                    str(details.get("os", "")),
                    str(details.get("hardware_version", "")),
                    str(details.get("software_version", "")),
                    1 if mac in reservations else 0,
                    str(reservation.get("ip", "")),
                    str(reservation.get("description", "")),
                    int(reservation.get("id", 0) or 0),
                    str(details.get("unifi_name", "")),
                    str(
                        details.get(
                            "unifi_connection_type",
                            "",
                        )
                    ),
                    str(details.get("unifi_uplink_id", "")),
                    str(details.get("unifi_uplink_name", "")),
                    str(details.get("unifi_model", "")),
                    str(details.get("unifi_firmware", "")),
                    str(details.get("unifi_state", "")),
                    int(details.get("unifi_managed", 0) or 0),
                    now,
                ),
            )

    with db() as conn:
        categorized = auto_categorize_unknown_devices(conn)

    message = (
        f"Updated {len(by_mac)} MAC records: "
        f"{len(reservations)} FortiGate reservations, "
        f"{len(unifi_devices)} UniFi devices, "
        f"{len(unifi_clients)} UniFi clients; "
        f"auto-categorized {categorized} devices."
    )

    return len(by_mac), message


def add_like_filter(
    sql: str,
    args: list[Any],
    column: str,
    value: str,
) -> str:
    if not value:
        return sql

    sql += f" AND LOWER({column}) LIKE ?"
    args.append(
        f"%{value.strip().lower()}%"
    )

    return sql


def query_rows(
    filters: dict[str, str],
    sort_by: str,
    sort_order: str,
) -> tuple[
    list[sqlite3.Row],
    sqlite3.Row,
]:
    sql = """
        SELECT
            m.*,
            d.logical_name,
            d.category,
            d.location,
            d.notes
        FROM device_macs m
        JOIN devices d
            ON d.device_id=m.device_id
        WHERE 1=1
    """

    args: list[Any] = []

    q = filters.get(
        "q",
        "",
    ).strip()

    if q:
        sql += """
            AND (
                LOWER(m.current_ip) LIKE ?
                OR LOWER(m.ip_source) LIKE ?
                OR LOWER(m.reserved_ip) LIKE ?
                OR LOWER(m.mac) LIKE ?
                OR LOWER(m.hostname) LIKE ?
                OR LOWER(m.vendor) LIKE ?
                OR LOWER(m.type) LIKE ?
                OR LOWER(m.family) LIKE ?
                OR LOWER(m.os) LIKE ?
                OR LOWER(m.unifi_name) LIKE ?
                OR LOWER(m.unifi_model) LIKE ?
                OR LOWER(m.unifi_connection_type) LIKE ?
                OR LOWER(m.unifi_uplink_name) LIKE ?
                OR LOWER(m.unifi_state) LIKE ?
                OR LOWER(d.logical_name) LIKE ?
                OR LOWER(d.location) LIKE ?
                OR LOWER(d.notes) LIKE ?
            )
        """

        term = f"%{q.lower()}%"
        args.extend(
            [term] * 17
        )

    text_filters = {
        "current_ip": "m.current_ip",
        "ip_source": "m.ip_source",
        "reserved_ip": "m.reserved_ip",
        "mac": "m.mac",
        "hostname": "m.hostname",
        "unifi_name": "m.unifi_name",
        "connection": "m.unifi_connection_type",
        "uplink": "m.unifi_uplink_name",
        "unifi_model": "m.unifi_model",
        "unifi_firmware": "m.unifi_firmware",
        "unifi_state": "m.unifi_state",
        "vendor": "m.vendor",
        "type": "m.type",
        "family": "m.family",
        "os": "m.os",
        "hardware_version": "m.hardware_version",
        "software_version": "m.software_version",
        "logical_name": "d.logical_name",
        "location": "d.location",
        "notes": "d.notes",
        "proposed_ip": "m.proposed_ip",
        "reservation_description":
            "m.reservation_description",
    }

    for filter_name, column in text_filters.items():
        sql = add_like_filter(
            sql,
            args,
            column,
            filters.get(
                filter_name,
                "",
            ),
        )

    category = filters.get(
        "category",
        "",
    )

    if category:
        sql += " AND d.category=?"
        args.append(category)

    reservation = filters.get(
        "reservation",
        "",
    )

    if reservation == "reserved":
        sql += " AND m.reserved=1"
    elif reservation == "unreserved":
        sql += " AND m.reserved=0"

    sort_column = SORT_COLUMNS.get(
        sort_by,
        "m.current_ip",
    )

    direction = (
        "DESC"
        if sort_order.lower() == "desc"
        else "ASC"
    )

    ip_sort_columns = {
        "current_ip",
        "reserved_ip",
        "proposed_ip",
    }

    blank_last = (
        f"CASE WHEN {sort_column} IS NULL "
        f"OR TRIM({sort_column}) = '' "
        "THEN 1 ELSE 0 END ASC"
    )

    if sort_by in ip_sort_columns:
        primary_sort = (
            f"{blank_last}, "
            f"IP_SORT({sort_column}) {direction}, "
            f"{sort_column} {direction}"
        )
    else:
        primary_sort = (
            f"{blank_last}, "
            f"LOWER({sort_column}) {direction}"
        )

    current_ip_sort = (
        "CASE WHEN m.current_ip IS NULL "
        "OR TRIM(m.current_ip) = '' "
        "THEN 1 ELSE 0 END ASC, "
        "IP_SORT(m.current_ip) ASC, "
        "m.current_ip ASC"
    )

    if sort_by == "current_ip":
        sql += (
            f" ORDER BY {primary_sort}, "
            "m.mac ASC"
        )
    else:
        sql += (
            f" ORDER BY {primary_sort}, "
            f"{current_ip_sort}, "
            "m.mac ASC"
        )

    with db() as conn:
        rows = conn.execute(
            sql,
            args,
        ).fetchall()

        totals = conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(reserved) AS reserved,
                SUM(
                    CASE
                        WHEN reserved=0 THEN 1
                        ELSE 0
                    END
                ) AS unreserved
            FROM device_macs
            """
        ).fetchone()

    return rows, totals


@app.get("/")
def index(
    request: Request,
    q: str = "",
    current_ip: str = "",
    ip_source: str = "",
    reserved_ip: str = "",
    mac: str = "",
    hostname: str = "",
    unifi_name: str = "",
    connection: str = "",
    uplink: str = "",
    unifi_model: str = "",
    unifi_firmware: str = "",
    unifi_state: str = "",
    vendor: str = "",
    type: str = "",
    family: str = "",
    os: str = "",
    hardware_version: str = "",
    software_version: str = "",
    logical_name: str = "",
    category: str = "",
    location: str = "",
    notes: str = "",
    proposed_ip: str = "",
    reservation_description: str = "",
    reservation: str = "",
    sort_by: str = "current_ip",
    sort_order: str = "asc",
    message: str = "",
):
    filters = {
        "q": q,
        "current_ip": current_ip,
        "ip_source": ip_source,
        "reserved_ip": reserved_ip,
        "mac": mac,
        "hostname": hostname,
        "unifi_name": unifi_name,
        "connection": connection,
        "uplink": uplink,
        "unifi_model": unifi_model,
        "unifi_firmware": unifi_firmware,
        "unifi_state": unifi_state,
        "vendor": vendor,
        "type": type,
        "family": family,
        "os": os,
        "hardware_version": hardware_version,
        "software_version": software_version,
        "logical_name": logical_name,
        "category": category,
        "location": location,
        "notes": notes,
        "proposed_ip": proposed_ip,
        "reservation_description":
            reservation_description,
        "reservation": reservation,
    }

    rows, totals = query_rows(
        filters,
        sort_by,
        sort_order,
    )

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "view": "inventory",
            "rows": rows,
            "totals": totals,
            "categories": CATEGORIES,
            "filters": filters,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "message": message,
            "change_file_exists":
                CHANGE_FILE.exists(),
        },
    )



def load_indexed_file(path: Path, prefix: str) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith(prefix) and key[len(prefix):].isdigit():
            values[key] = value
    return values


def ssh_run(client: paramiko.SSHClient, command: str) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=30)
    status = stdout.channel.recv_exit_status()
    return (
        status,
        stdout.read().decode("utf-8", errors="replace").strip(),
        stderr.read().decode("utf-8", errors="replace").strip(),
    )


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key] = value.strip().strip('"')
    return out


def first_device_ip(device_id: str) -> str:
    with db() as conn:
        row = conn.execute(
            """
            SELECT current_ip, reserved_ip
            FROM device_macs
            WHERE device_id=?
              AND (current_ip <> '' OR reserved_ip <> '')
            ORDER BY
              CASE WHEN current_ip <> '' THEN 0 ELSE 1 END,
              IP_SORT(COALESCE(NULLIF(current_ip, ''), reserved_ip))
            LIMIT 1
            """,
            (device_id,),
        ).fetchone()
    if not row:
        return ""
    return (row["current_ip"] or row["reserved_ip"] or "").strip()


def summarize_gpu_models(models: list[str]) -> str:
    counts: dict[str, int] = {}
    for model in models:
        clean = " ".join(str(model).split()).strip()
        if not clean:
            continue
        counts[clean] = counts.get(clean, 0) + 1
    return ", ".join(
        f"{model} ({count})"
        for model, count in sorted(counts.items(), key=lambda item: item[0].lower())
    )


def collect_host_gpus(client: paramiko.SSHClient) -> tuple[str, list[str]]:
    models: list[str] = []
    _, nvidia_text, _ = ssh_run(
        client,
        "nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null || true",
    )
    for line in nvidia_text.splitlines():
        name = line.strip()
        if name and name not in models:
            # Keep repeated models so counts remain accurate.
            pass
        if name:
            models.append(name)

    _, pci_text, _ = ssh_run(
        client,
        "lspci 2>/dev/null | grep -Ei 'VGA compatible controller|3D controller|Display controller' || true",
    )
    for line in pci_text.splitlines():
        description = line.split(": ", 1)[-1].strip()
        if not description:
            continue
        # Avoid counting NVIDIA twice when nvidia-smi already supplied exact models.
        if "nvidia" in description.lower() and any("nvidia" in x.lower() for x in models):
            continue
        models.append(description)

    return summarize_gpu_models(models), models


def container_gpu_summary(raw: dict[str, Any], host_gpu_summary: str) -> str:
    host_config = raw.get("host_config") or {}
    device_requests = host_config.get("device_requests") or []
    devices = host_config.get("devices") or []

    for request in device_requests:
        if not isinstance(request, dict):
            continue
        driver = str(request.get("Driver") or request.get("driver") or "").lower()
        capabilities = str(request.get("Capabilities") or request.get("capabilities") or "").lower()
        if driver == "nvidia" or "gpu" in capabilities:
            count = request.get("Count", request.get("count", 0))
            device_ids = request.get("DeviceIDs", request.get("device_ids", [])) or []
            if device_ids:
                return f"NVIDIA GPU ({len(device_ids)})"
            try:
                count_int = int(count)
            except (TypeError, ValueError):
                count_int = 0
            if count_int == -1:
                return host_gpu_summary or "NVIDIA GPU (all)"
            if count_int > 0:
                return f"NVIDIA GPU ({count_int})"
            return host_gpu_summary or "NVIDIA GPU"

    dri_count = 0
    for device in devices:
        if not isinstance(device, dict):
            continue
        path = str(device.get("PathOnHost") or device.get("path_on_host") or "")
        if path.startswith("/dev/dri"):
            dri_count += 1
    if dri_count:
        return f"DRI GPU ({dri_count})"
    return ""


def collect_system_facts(client: paramiko.SSHClient) -> dict[str, Any]:
    facts: dict[str, Any] = {}

    _, hostname, _ = ssh_run(client, "hostname -f 2>/dev/null || hostname")
    facts["hostname"] = hostname.splitlines()[0] if hostname else ""

    _, os_text, _ = ssh_run(client, "cat /etc/os-release 2>/dev/null || true")
    os_data = parse_os_release(os_text)
    facts["os_name"] = os_data.get("NAME", "")
    facts["os_version"] = os_data.get("VERSION", os_data.get("VERSION_ID", ""))

    _, kernel, _ = ssh_run(client, "uname -r")
    facts["kernel"] = kernel

    _, cpu_json, _ = ssh_run(client, "lscpu -J 2>/dev/null || true")
    cpu: dict[str, str] = {}
    try:
        for item in json.loads(cpu_json or "{}").get("lscpu", []):
            cpu[str(item.get("field", "")).rstrip(":")] = str(item.get("data", ""))
    except Exception:
        pass
    facts["cpu_model"] = cpu.get("Model name", "")
    facts["cpu_sockets"] = int(cpu.get("Socket(s)", "0") or 0)
    facts["cpu_cores"] = int(cpu.get("Core(s) per socket", "0") or 0) * max(facts["cpu_sockets"], 1)
    facts["cpu_threads"] = int(cpu.get("CPU(s)", "0") or 0)

    facts["gpu_summary"], facts["gpu_models"] = collect_host_gpus(client)

    _, mem_text, _ = ssh_run(client, "awk '/MemTotal:/ {print $2*1024}' /proc/meminfo")
    try:
        facts["memory_total"] = int(float(mem_text or "0"))
    except ValueError:
        facts["memory_total"] = 0

    _, uptime_text, _ = ssh_run(client, "cut -d. -f1 /proc/uptime")
    try:
        facts["uptime_seconds"] = int(uptime_text or "0")
    except ValueError:
        facts["uptime_seconds"] = 0

    _, interfaces_text, _ = ssh_run(client, "ip -j addr 2>/dev/null || echo '[]'")
    try:
        facts["interfaces"] = json.loads(interfaces_text or "[]")
    except Exception:
        facts["interfaces"] = []

    _, disks_text, _ = ssh_run(
        client,
        "lsblk -J -b -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,FSUSED,FSAVAIL,MODEL,SERIAL 2>/dev/null || echo '{\"blockdevices\":[]}'",
    )
    try:
        facts["disks"] = json.loads(disks_text or "{}").get("blockdevices", [])
    except Exception:
        facts["disks"] = []

    docker: dict[str, Any] = {"installed": False, "containers": []}
    docker_command = r"""
if command -v docker >/dev/null 2>&1; then
    docker ps -aq | xargs -r docker inspect --size --format '{"name":{{json .Name}},"state":{{json .State.Status}},"network_mode":{{json .HostConfig.NetworkMode}},"ports":{{json .NetworkSettings.Ports}},"networks":{{json .NetworkSettings.Networks}},"size_rw":{{json .SizeRw}},"size_rootfs":{{json .SizeRootFs}},"image":{{json .Config.Image}},"host_config":{"device_requests":{{json .HostConfig.DeviceRequests}},"devices":{{json .HostConfig.Devices}}}}'
fi
"""
    _, docker_text, _ = ssh_run(client, docker_command)
    if docker_text:
        docker["installed"] = True
        stats_by_name: dict[str, dict[str, str]] = {}
        stats_command = r"""
if command -v docker >/dev/null 2>&1; then
    docker stats --no-stream --format '{{json .}}' 2>/dev/null || true
fi
"""
        _, stats_text, _ = ssh_run(client, stats_command)
        for line in stats_text.splitlines():
            try:
                stat = json.loads(line)
                stat_name = str(stat.get("Name") or stat.get("Container") or "").lstrip("/")
                if stat_name:
                    stats_by_name[stat_name] = {
                        "cpu_percent": str(stat.get("CPUPerc") or ""),
                        "memory_usage": str(stat.get("MemUsage") or ""),
                        "memory_percent": str(stat.get("MemPerc") or ""),
                    }
            except Exception:
                continue

        for line in docker_text.splitlines():
            try:
                item = json.loads(line)
                item["name"] = str(item.get("name", "")).lstrip("/")
                item.update(stats_by_name.get(item["name"], {}))
                docker["containers"].append(item)
            except Exception:
                continue
    facts["docker"] = docker
    return facts




def tcp_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def normalize_windows_items(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def collect_windows_facts(session: winrm.Session) -> dict[str, Any]:
    script = r'''$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cpus = @(Get-CimInstance Win32_Processor)
$gpus = @(Get-CimInstance Win32_VideoController | Where-Object { $_.Name })
$nics = @(Get-NetIPConfiguration | ForEach-Object {
    $a = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex
    [pscustomobject]@{
        ifname = $_.InterfaceAlias
        address = $a.MacAddress
        operstate = $a.Status
        mtu = (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).NlMtu
        link_type = $a.MediaType
        addr_info = @($_.AllIPAddresses | ForEach-Object {
            [pscustomobject]@{ local = $_.IPAddress; prefixlen = $_.PrefixLength; family = $_.AddressFamily.ToString() }
        })
    }
})
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    [pscustomobject]@{
        name = $_.DeviceID
        type = 'volume'
        model = ''
        serial = $_.VolumeSerialNumber
        mountpoint = ($_.DeviceID + '\')
        fstype = $_.FileSystem
        size = [int64]$_.Size
        fsused = [int64]($_.Size - $_.FreeSpace)
        fsavail = [int64]$_.FreeSpace
        children = @()
    }
})
$dockerInstalled = $false
$containers = @()
if (Get-Command docker -ErrorAction SilentlyContinue) {
    $dockerInstalled = $true
    $names = @(docker ps -a --format '{{.Names}}' 2>$null)
    foreach ($name in $names) {
        $inspect = docker inspect --size $name 2>$null | ConvertFrom-Json | Select-Object -First 1
        $stats = docker stats --no-stream --format '{{json .}}' $name 2>$null | ConvertFrom-Json
        $ports = @{}
        if ($inspect.NetworkSettings.Ports) {
            foreach ($prop in $inspect.NetworkSettings.Ports.PSObject.Properties) { $ports[$prop.Name] = $prop.Value }
        }
        $networks = @{}
        if ($inspect.NetworkSettings.Networks) {
            foreach ($prop in $inspect.NetworkSettings.Networks.PSObject.Properties) {
                $networks[$prop.Name] = @{ IPAddress = $prop.Value.IPAddress }
            }
        }
        $containers += [pscustomobject]@{
            name = $name
            state = $inspect.State.Status
            network_mode = $inspect.HostConfig.NetworkMode
            ports = $ports
            networks = $networks
            image = $inspect.Config.Image
            size_rw = [int64]$inspect.SizeRw
            size_rootfs = [int64]$inspect.SizeRootFs
            cpu_percent = $stats.CPUPerc
            memory_usage = $stats.MemUsage
            memory_percent = $stats.MemPerc
            gpu_summary = ''
        }
    }
}
[pscustomobject]@{
    hostname = $env:COMPUTERNAME
    os_name = $os.Caption
    os_version = $os.Version
    kernel = $os.BuildNumber
    cpu_model = (($cpus | Select-Object -ExpandProperty Name -Unique) -join '; ')
    cpu_sockets = @($cpus).Count
    cpu_cores = [int](($cpus | Measure-Object NumberOfCores -Sum).Sum)
    cpu_threads = [int](($cpus | Measure-Object NumberOfLogicalProcessors -Sum).Sum)
    gpu_models = @($gpus | Select-Object -ExpandProperty Name)
    memory_total = [int64]$cs.TotalPhysicalMemory
    uptime_seconds = [int64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
    interfaces = $nics
    disks = $disks
    docker = @{ installed = $dockerInstalled; containers = $containers }
} | ConvertTo-Json -Depth 8 -Compress'''
    response = session.run_ps(script)
    if response.status_code != 0:
        error = response.std_err.decode("utf-8", errors="replace").strip()
        raise RuntimeError(error or f"PowerShell exited with status {response.status_code}")
    data = json.loads(response.std_out.decode("utf-8", errors="replace").strip())
    data["interfaces"] = normalize_windows_items(data.get("interfaces"))
    data["disks"] = normalize_windows_items(data.get("disks"))
    docker = data.get("docker") or {}
    docker["containers"] = normalize_windows_items(docker.get("containers"))
    data["docker"] = docker
    models = data.pop("gpu_models", [])
    if isinstance(models, str):
        models = [models]
    data["gpu_summary"] = summarize_gpu_models([str(x) for x in models if x])
    return data


def save_scan_success(device_id: str, target_ip: str, facts: dict[str, Any], user_key: str, pass_key: str, method: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        merged_devices = merge_discovered_interfaces(conn, device_id, facts.get("interfaces", []))
        replace_system_children(conn, device_id, facts)
        conn.execute(
            "INSERT INTO host_credentials(device_id,user_key,password_key,last_success,last_failure,last_error,scan_method) VALUES(?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET user_key=excluded.user_key,password_key=excluded.password_key,last_success=excluded.last_success,last_error='',scan_method=excluded.scan_method",
            (device_id,user_key,pass_key,now,"","",method),
        )
        conn.execute(
            "INSERT INTO system_facts(device_id,scan_ip,hostname,os_name,os_version,kernel,cpu_model,cpu_sockets,cpu_cores,cpu_threads,gpu_summary,memory_total,uptime_seconds,interfaces_json,disks_json,docker_json,scanned_at,scan_status,scan_error,scan_method) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET scan_ip=excluded.scan_ip,hostname=excluded.hostname,os_name=excluded.os_name,os_version=excluded.os_version,kernel=excluded.kernel,cpu_model=excluded.cpu_model,cpu_sockets=excluded.cpu_sockets,cpu_cores=excluded.cpu_cores,cpu_threads=excluded.cpu_threads,gpu_summary=excluded.gpu_summary,memory_total=excluded.memory_total,uptime_seconds=excluded.uptime_seconds,interfaces_json=excluded.interfaces_json,disks_json=excluded.disks_json,docker_json=excluded.docker_json,scanned_at=excluded.scanned_at,scan_status='success',scan_error='',scan_method=excluded.scan_method",
            (device_id,target_ip,facts.get("hostname",""),facts.get("os_name",""),facts.get("os_version",""),facts.get("kernel",""),facts.get("cpu_model",""),int(facts.get("cpu_sockets") or 0),int(facts.get("cpu_cores") or 0),int(facts.get("cpu_threads") or 0),facts.get("gpu_summary",""),int(facts.get("memory_total") or 0),int(facts.get("uptime_seconds") or 0),json.dumps(facts.get("interfaces") or []),json.dumps(facts.get("disks") or []),json.dumps(facts.get("docker") or {}),now,"success","",method),
        )
    return merged_devices


def save_scan_failure(device_id: str, target_ip: str, error: str, method: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute("INSERT INTO host_credentials(device_id,last_failure,last_error,scan_method) VALUES(?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET last_failure=excluded.last_failure,last_error=excluded.last_error,scan_method=excluded.scan_method", (device_id,now,error,method))
        conn.execute("INSERT INTO system_facts(device_id,scan_ip,scanned_at,scan_status,scan_error,scan_method) VALUES(?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET scan_ip=excluded.scan_ip,scanned_at=excluded.scanned_at,scan_status='failed',scan_error=excluded.scan_error,scan_method=excluded.scan_method", (device_id,target_ip,now,"failed",error,method))


def credential_attempts(users: dict[str,str], passwords: dict[str,str], saved: Any, method: str) -> list[tuple[str,str]]:
    attempts: list[tuple[str,str]] = []
    if saved and saved["scan_method"] == method and saved["user_key"] in users and saved["password_key"] in passwords:
        attempts.append((saved["user_key"],saved["password_key"]))
    for user_key in sorted(users,key=lambda x:int(x[1:])):
        for pass_key in sorted(passwords,key=lambda x:int(x[1:])):
            pair=(user_key,pass_key)
            if pair not in attempts:
                attempts.append(pair)
    return attempts


def ssh_port_open(host: str, port: int = SSH_PORT, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def normalize_mac(value: str) -> str:
    return str(value or '').strip().lower()


def merge_discovered_interfaces(
    conn: sqlite3.Connection,
    target_device_id: str,
    interfaces: list[dict[str, Any]],
) -> int:
    discovered_macs = {
        normalize_mac(item.get('address', ''))
        for item in interfaces
        if normalize_mac(item.get('address', '')) not in ('', '00:00:00:00:00:00')
    }
    merged = 0
    for mac in discovered_macs:
        row = conn.execute(
            "SELECT device_id FROM device_macs WHERE LOWER(mac)=?",
            (mac,),
        ).fetchone()
        if not row or row['device_id'] == target_device_id:
            continue
        source_device_id = row['device_id']
        target = conn.execute(
            "SELECT logical_name,category,location,notes FROM devices WHERE device_id=?",
            (target_device_id,),
        ).fetchone()
        source = conn.execute(
            "SELECT logical_name,category,location,notes FROM devices WHERE device_id=?",
            (source_device_id,),
        ).fetchone()
        if target and source:
            conn.execute(
                """
                UPDATE devices SET
                    logical_name=CASE WHEN logical_name='' THEN ? ELSE logical_name END,
                    category=CASE WHEN category IN ('','Unknown') THEN ? ELSE category END,
                    location=CASE WHEN location='' THEN ? ELSE location END,
                    notes=CASE WHEN notes='' THEN ? ELSE notes END
                WHERE device_id=?
                """,
                (
                    source['logical_name'], source['category'],
                    source['location'], source['notes'], target_device_id,
                ),
            )
        conn.execute(
            "UPDATE device_macs SET device_id=? WHERE device_id=?",
            (target_device_id, source_device_id),
        )
        conn.execute("DELETE FROM system_interfaces WHERE device_id=?", (source_device_id,))
        conn.execute("DELETE FROM system_disks WHERE device_id=?", (source_device_id,))
        conn.execute("DELETE FROM docker_containers WHERE device_id=?", (source_device_id,))
        conn.execute("DELETE FROM system_facts WHERE device_id=?", (source_device_id,))
        conn.execute("DELETE FROM host_credentials WHERE device_id=?", (source_device_id,))
        conn.execute("DELETE FROM devices WHERE device_id=?", (source_device_id,))
        merged += 1
    return merged


def replace_system_children(
    conn: sqlite3.Connection,
    device_id: str,
    facts: dict[str, Any],
) -> None:
    conn.execute("DELETE FROM system_interfaces WHERE device_id=?", (device_id,))
    conn.execute("DELETE FROM system_disks WHERE device_id=?", (device_id,))
    conn.execute("DELETE FROM docker_containers WHERE device_id=?", (device_id,))

    for item in facts.get('interfaces', []):
        if not isinstance(item, dict):
            continue
        conn.execute(
            """
            INSERT INTO system_interfaces(
                device_id,ifname,mac,state,mtu,link_type,addresses_json
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                device_id, str(item.get('ifname','')),
                normalize_mac(item.get('address','')),
                str(item.get('operstate','')), int(item.get('mtu') or 0),
                str(item.get('link_type','')),
                json.dumps(item.get('addr_info') or []),
            ),
        )

    def add_disk(item: dict[str, Any], parent: str = '') -> None:
        if not isinstance(item, dict):
            return
        conn.execute(
            """
            INSERT OR REPLACE INTO system_disks(
                device_id,parent_name,name,device_type,model,serial,mountpoint,
                filesystem,size_bytes,used_bytes,free_bytes
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                device_id,parent,str(item.get('name','')),str(item.get('type','')),
                str(item.get('model') or ''),str(item.get('serial') or ''),
                str(item.get('mountpoint') or ''),str(item.get('fstype') or ''),
                int(item.get('size') or 0),int(item.get('fsused') or 0),
                int(item.get('fsavail') or 0),
            ),
        )
        for child in item.get('children') or []:
            add_disk(child, str(item.get('name','')))

    for disk in facts.get('disks', []):
        add_disk(disk)

    docker = facts.get('docker') or {}
    for item in docker.get('containers') or []:
        networks = item.get('networks') or {}
        ip_address = ''
        if isinstance(networks, dict):
            for network in networks.values():
                if isinstance(network, dict) and network.get('IPAddress'):
                    ip_address = str(network.get('IPAddress'))
                    break
        ports = item.get('ports') or {}
        conn.execute(
            """
            INSERT INTO docker_containers(
                device_id,name,state,network_mode,ip_address,ports,image,size_rw,size_rootfs,
                cpu_percent,memory_usage,memory_percent,gpu_summary
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                device_id,str(item.get('name','')),str(item.get('state','')),
                str(item.get('network_mode','')),ip_address,json.dumps(ports),
                str(item.get('image','')),int(item.get('size_rw') or 0),
                int(item.get('size_rootfs') or 0),
                str(item.get('cpu_percent','')),str(item.get('memory_usage','')),
                str(item.get('memory_percent','')),
                str(item.get('gpu_summary','')),
            ),
        )


def scan_device(device_id: str) -> tuple[bool, str]:
    target_ip = first_device_ip(device_id)
    if not target_ip:
        return False, "No current or reserved IP is available for this device"

    with db() as conn:
        saved = conn.execute("SELECT user_key,password_key,scan_method FROM host_credentials WHERE device_id=?", (device_id,)).fetchone()

    errors: list[str] = []
    ssh_open = tcp_port_open(target_ip, SSH_PORT)
    if ssh_open:
        users = load_indexed_file(LIN_USERS_FILE, "u")
        passwords = load_indexed_file(LIN_PASSWORDS_FILE, "p")
        if users and passwords:
            for user_key, pass_key in credential_attempts(users, passwords, saved, "SSH"):
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(hostname=target_ip,port=SSH_PORT,username=users[user_key],password=passwords[pass_key],timeout=SSH_TIMEOUT,banner_timeout=SSH_TIMEOUT,auth_timeout=SSH_TIMEOUT,look_for_keys=False,allow_agent=False)
                    facts = collect_system_facts(client)
                    merged = save_scan_success(device_id,target_ip,facts,user_key,pass_key,"SSH")
                    note = f"; merged {merged} interface device record(s)" if merged else ""
                    return True, f"Scanned {target_ip} via SSH using {user_key}/{pass_key}{note}"
                except Exception as exc:
                    errors.append(f"SSH {user_key}/{pass_key}: {exc}")
                finally:
                    client.close()
        else:
            errors.append("SSH: lin-users.key or lin-passwords.key is missing/empty")

    https_open = tcp_port_open(target_ip, WINRM_HTTPS_PORT)
    http_open = tcp_port_open(target_ip, WINRM_HTTP_PORT)
    winrm_port = WINRM_HTTPS_PORT if https_open else (WINRM_HTTP_PORT if http_open else 0)
    if winrm_port:
        users = load_indexed_file(WIN_USERS_FILE, "u")
        passwords = load_indexed_file(WIN_PASSWORDS_FILE, "p")
        if users and passwords:
            protocol = "https" if winrm_port == WINRM_HTTPS_PORT else "http"
            endpoint = f"{protocol}://{target_ip}:{winrm_port}/wsman"
            for user_key, pass_key in credential_attempts(users, passwords, saved, "WinRM"):
                try:
                    session = winrm.Session(endpoint,auth=(users[user_key],passwords[pass_key]),transport="ntlm",server_cert_validation="validate" if WINRM_VERIFY_TLS else "ignore",read_timeout_sec=max(WINRM_TIMEOUT,10),operation_timeout_sec=max(WINRM_TIMEOUT-5,5))
                    facts = collect_windows_facts(session)
                    merged = save_scan_success(device_id,target_ip,facts,user_key,pass_key,"WinRM")
                    note = f"; merged {merged} interface device record(s)" if merged else ""
                    return True, f"Scanned {target_ip} via WinRM using {user_key}/{pass_key}{note}"
                except Exception as exc:
                    errors.append(f"WinRM {user_key}/{pass_key}: {exc}")
        else:
            errors.append("WinRM: win-users.key or win-passwords.key is missing/empty")

    if not ssh_open and not winrm_port:
        error = f"No reachable SSH ({SSH_PORT}) or WinRM ({WINRM_HTTP_PORT}/{WINRM_HTTPS_PORT}) service"
        save_scan_failure(device_id,target_ip,error,"")
        return False,error

    error = errors[-1] if errors else "No credential combination succeeded"
    save_scan_failure(device_id,target_ip,error,"WinRM" if winrm_port else "SSH")
    return False,error


def format_ports(value: Any) -> str:
    """Format Docker inspect port mappings for compact display."""
    if not value:
        return "-"

    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return value.strip() or "-"

    if not isinstance(value, dict):
        return str(value)

    mappings: list[str] = []

    def port_sort_key(item: tuple[str, Any]) -> tuple[int, str]:
        container_port = item[0]
        number = container_port.split("/", 1)[0]
        try:
            return int(number), container_port
        except ValueError:
            return 65536, container_port

    for container_port, bindings in sorted(value.items(), key=port_sort_key):
        if not bindings:
            continue

        protocol = ""
        port_only = str(container_port)
        if "/" in port_only:
            port_only, protocol = port_only.split("/", 1)

        if not isinstance(bindings, list):
            bindings = [bindings]

        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            host_ip = str(binding.get("HostIp") or "")
            host_port = str(binding.get("HostPort") or "")
            if not host_port:
                continue

            if host_ip in ("", "0.0.0.0", "::"):
                displayed = f"{host_port}:{port_only}"
            else:
                displayed = f"{host_ip}:{host_port}:{port_only}"

            if protocol and protocol.lower() != "tcp":
                displayed += f"/{protocol}"
            mappings.append(displayed)

    return "\n".join(mappings) if mappings else "-"


def format_bytes(value: Any) -> str:
    try:
        size = float(value or 0)
    except (TypeError, ValueError):
        return ""
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    unit = 0
    while size >= 1024 and unit < len(units) - 1:
        size /= 1024
        unit += 1
    if unit == 0:
        return f"{int(size)} {units[unit]}"
    return f"{size:.2f} {units[unit]}"


def compact_interfaces(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for interface in items or []:
        name = str(interface.get("ifname", ""))
        if not name or name == "lo":
            continue
        # Docker-created bridge and veth interfaces are represented in the
        # Docker section instead of cluttering the host interface summary.
        if (
            name == "docker0"
            or name.startswith("br-")
            or name.startswith("veth")
        ):
            continue
        addresses: list[dict[str, str]] = []
        for address in interface.get("addr_info", []) or []:
            family = str(address.get("family", ""))
            local = str(address.get("local", ""))
            if not local:
                continue
            prefix = address.get("prefixlen")
            value = f"{local}/{prefix}" if prefix is not None else local
            if family == "inet":
                method = "DHCP" if address.get("dynamic") else "STATIC"
                label = "IPv4"
            elif family == "inet6":
                method = "LINK-LOCAL" if address.get("scope") == "link" else "STATIC"
                label = "IPv6"
            else:
                method = ""
                label = family.upper() or "IP"
            addresses.append({"label": label, "value": value, "method": method})
        output.append(
            {
                "name": name,
                "state": str(interface.get("operstate", "UNKNOWN")),
                "mtu": interface.get("mtu", ""),
                "mac": str(interface.get("address", "")),
                "addresses": addresses,
            }
        )
    return output


def compact_disks(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for device in items or []:
        name = str(device.get("name", ""))
        dev_type = str(device.get("type", ""))
        fstype = str(device.get("fstype") or "")
        mountpoint = str(device.get("mountpoint") or "")
        if dev_type == "loop" or name.startswith("loop") or fstype == "squashfs" or mountpoint.startswith("/snap/"):
            continue
        if dev_type == "disk":
            output.append(
                {
                    "kind": "disk",
                    "name": name,
                    "model": str(device.get("model") or "").strip(),
                    "serial": str(device.get("serial") or "").strip(),
                    "capacity": format_bytes(device.get("size")),
                }
            )
        candidates = device.get("children", []) or []
        if dev_type != "disk":
            candidates = [device]
        for child in candidates:
            child_name = str(child.get("name", ""))
            child_type = str(child.get("type", ""))
            child_fs = str(child.get("fstype") or "")
            child_mount = str(child.get("mountpoint") or "")
            if child_type == "loop" or child_name.startswith("loop") or child_fs == "squashfs" or child_mount.startswith("/snap/"):
                continue
            output.append(
                {
                    "kind": "volume",
                    "name": child_name,
                    "mountpoint": child_mount or "-",
                    "fstype": child_fs or "-",
                    "capacity": format_bytes(child.get("size")),
                    "free": format_bytes(child.get("fsavail")),
                }
            )
    return output


def compact_docker(data: dict[str, Any]) -> dict[str, Any]:
    containers: list[dict[str, Any]] = []
    running = 0
    for raw in (data or {}).get("containers", []) or []:
        name = str(raw.get("name") or raw.get("Names") or "").lstrip("/")
        state = str(raw.get("state") or raw.get("State") or raw.get("Status") or "")
        if state.lower() == "running" or state.lower().startswith("up "):
            running += 1
        network_mode = str(raw.get("network_mode") or "")
        ips: list[str] = []
        networks = raw.get("networks") or {}
        if isinstance(networks, dict):
            for details in networks.values():
                if isinstance(details, dict):
                    ip = str(details.get("IPAddress") or "")
                    if ip and ip not in ips:
                        ips.append(ip)
        ip_display = ", ".join(ips) if ips else "HOST-IP"
        if network_mode == "host":
            ip_display = "HOST-IP"

        ports_value = raw.get("ports")
        port_parts: list[str] = []
        if isinstance(ports_value, dict):
            for container_port, mappings in ports_value.items():
                if not mappings:
                    port_parts.append(str(container_port))
                    continue
                for mapping in mappings:
                    host_ip = str(mapping.get("HostIp") or "")
                    host_port = str(mapping.get("HostPort") or "")
                    prefix = "" if host_ip in ("", "0.0.0.0", "::") else f"{host_ip}:"
                    port_parts.append(f"{prefix}{host_port}:{container_port}")
        elif ports_value:
            port_parts.append(str(ports_value))

        size = raw.get("size_rootfs") or raw.get("SizeRootFs") or raw.get("Size") or ""
        containers.append(
            {
                "name": name,
                "state": state,
                "ip": ip_display,
                "ports": ", ".join(port_parts) or "-",
                "size": format_bytes(size) if isinstance(size, (int, float)) else str(size),
                "image": str(raw.get("image") or raw.get("Image") or ""),
            }
        )
    return {
        "installed": bool((data or {}).get("installed")),
        "total": len(containers),
        "running": running,
        "stopped": max(len(containers) - running, 0),
        "containers": containers,
    }

def query_systems(show_failures: bool = False) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT
                d.device_id,d.logical_name,d.category,d.location,
                s.scan_ip,s.hostname,s.os_name,s.os_version,s.kernel,s.scan_method,
                s.cpu_model,s.cpu_sockets,s.cpu_cores,s.cpu_threads,s.gpu_summary,
                s.memory_total,s.uptime_seconds,s.interfaces_json,s.disks_json,
                s.docker_json,s.scanned_at,s.scan_status,s.scan_error,
                h.user_key,h.password_key,h.scan_method AS credential_method
            FROM devices d
            LEFT JOIN system_facts s ON s.device_id=d.device_id
            LEFT JOIN host_credentials h ON h.device_id=d.device_id
            WHERE s.device_id IS NOT NULL
              AND (? = 1 OR s.scan_status = 'success')
            ORDER BY CASE WHEN d.logical_name='' THEN 1 ELSE 0 END,
                     LOWER(d.logical_name), s.scan_ip
            """
            , (1 if show_failures else 0,)
        ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        for key, default in (("interfaces_json", []), ("disks_json", []), ("docker_json", {})):
            try:
                item[key.removesuffix("_json")] = json.loads(item.get(key) or json.dumps(default))
            except Exception:
                item[key.removesuffix("_json")] = default
        item["compact_interfaces"] = compact_interfaces(item["interfaces"])
        item["compact_disks"] = compact_disks(item["disks"])
        item["compact_docker"] = compact_docker(item["docker"])
        result.append(item)
    return result


@app.post("/systems/scan/{device_id}")
def systems_scan(device_id: str):
    with db() as conn:
        row = conn.execute(
            "SELECT category FROM devices WHERE device_id=?",
            (device_id,),
        ).fetchone()
    category = row["category"] if row else ""
    if category not in SSH_SCAN_CATEGORIES:
        message = f"SSH scan excluded for category: {category or 'Unknown'}"
        return RedirectResponse(
            url=f"/devices?message={requests.utils.quote(message)}",
            status_code=303,
        )
    ok, message = scan_device(device_id)
    destination = "/systems" if ok else "/devices"
    return RedirectResponse(
        url=f"{destination}?message={requests.utils.quote(message)}",
        status_code=303,
    )


@app.post("/systems/scan-all")
def systems_scan_all():
    with db() as conn:
        device_ids = [
            row["device_id"]
            for row in conn.execute(
                """
                SELECT DISTINCT d.device_id
                FROM devices d
                JOIN device_macs m ON m.device_id=d.device_id
                WHERE d.category IN (
                    'Server',
                    'Desktop',
                    'Laptop',
                    'VM',
                    'Printer',
                    'Unknown'
                )
                  AND (
                      COALESCE(m.current_ip, '') <> ''
                      OR COALESCE(m.reserved_ip, '') <> ''
                  )
                ORDER BY d.logical_name, d.device_id
                """
            ).fetchall()
        ]

    scanned = 0
    failed = 0
    skipped = 0

    for device_id in device_ids:
        target_ip = first_device_ip(device_id)
        if not target_ip or not (tcp_port_open(target_ip, SSH_PORT) or tcp_port_open(target_ip, WINRM_HTTP_PORT) or tcp_port_open(target_ip, WINRM_HTTPS_PORT)):
            skipped += 1
            continue

        ok, _ = scan_device(device_id)
        if ok:
            scanned += 1
        else:
            failed += 1

    message = (
        f"Scan all complete for Server/Desktop/Laptop/VM/Printer/Unknown: "
        f"{scanned} succeeded, "
        f"{failed} failed authentication/collection, "
        f"{skipped} skipped with no reachable SSH or WinRM service."
    )

    return RedirectResponse(
        url=f"/systems?message={requests.utils.quote(message)}",
        status_code=303,
    )


def query_docker_containers(q: str = "", state: str = "", host: str = "") -> tuple[list[dict[str, Any]], dict[str, int]]:
    sql = """
        SELECT
            c.container_key,
            c.device_id,
            c.name,
            c.state,
            c.network_mode,
            c.ip_address,
            c.ports,
            c.image,
            c.size_rw,
            c.size_rootfs,
            c.cpu_percent,
            c.memory_usage,
            c.memory_percent,
            c.gpu_summary,
            d.logical_name,
            d.category,
            sf.hostname AS system_hostname,
            sf.scan_ip AS host_ip
        FROM docker_containers c
        JOIN devices d ON d.device_id=c.device_id
        LEFT JOIN system_facts sf ON sf.device_id=c.device_id
        WHERE 1=1
    """
    args: list[Any] = []
    if q.strip():
        term = f"%{q.strip().lower()}%"
        sql += """
            AND (
                LOWER(c.name) LIKE ? OR
                LOWER(c.image) LIKE ? OR
                LOWER(c.ip_address) LIKE ? OR
                LOWER(c.ports) LIKE ? OR
                LOWER(d.logical_name) LIKE ? OR
                LOWER(COALESCE(sf.hostname, '')) LIKE ?
            )
        """
        args.extend([term] * 6)
    if state.strip():
        sql += " AND LOWER(c.state)=?"
        args.append(state.strip().lower())
    if host.strip():
        term = f"%{host.strip().lower()}%"
        sql += " AND (LOWER(d.logical_name) LIKE ? OR LOWER(COALESCE(sf.hostname, '')) LIKE ? OR LOWER(COALESCE(sf.scan_ip, '')) LIKE ?)"
        args.extend([term, term, term])
    sql += " ORDER BY LOWER(COALESCE(NULLIF(d.logical_name,''), sf.hostname, sf.scan_ip)), LOWER(c.name)"

    with db() as conn:
        rows = conn.execute(sql, args).fetchall()

    result: list[dict[str, Any]] = []
    running = 0
    for row in rows:
        item = dict(row)
        if str(item.get("state", "")).lower() == "running":
            running += 1
        try:
            ports_data = json.loads(item.get("ports") or "{}")
        except Exception:
            ports_data = item.get("ports") or ""
        item["ports_display"] = format_ports(ports_data)
        item["display_ip"] = (
            "HOST-IP"
            if str(item.get("network_mode", "")).lower() == "host"
            else (item.get("ip_address") or "-")
        )
        size_value = int(item.get("size_rw") or 0)
        item["size_display"] = format_bytes(size_value) if size_value else "-"
        item["cpu_display"] = item.get("cpu_percent") or "-"
        memory_usage = item.get("memory_usage") or "-"
        memory_percent = item.get("memory_percent") or ""
        item["memory_display"] = (
            f"{memory_usage} ({memory_percent})" if memory_percent else memory_usage
        )
        item["gpu_display"] = item.get("gpu_summary") or "-"
        item["port_lines"] = str(item.get("ports_display") or "-").splitlines()
        item["host_display"] = item.get("logical_name") or item.get("system_hostname") or item.get("host_ip") or item.get("device_id")
        result.append(item)

    host_map: dict[str, dict[str, Any]] = {}
    for item in result:
        host_group = host_map.setdefault(
            item["device_id"],
            {
                "device_id": item["device_id"],
                "host_display": item["host_display"],
                "host_ip": item.get("host_ip") or "",
                "containers": [],
                "total": 0,
                "running": 0,
                "stopped": 0,
            },
        )
        host_group["containers"].append(item)
        host_group["total"] += 1
        if str(item.get("state", "")).lower() == "running":
            host_group["running"] += 1
        else:
            host_group["stopped"] += 1

    docker_hosts = sorted(
        host_map.values(),
        key=lambda host_item: str(host_item["host_display"]).lower(),
    )
    totals = {
        "total": len(result),
        "running": running,
        "stopped": len(result) - running,
        "hosts": len(docker_hosts),
    }
    return docker_hosts, totals


@app.get("/docker")
def docker_view(
    request: Request,
    q: str = "",
    state: str = "",
    host: str = "",
    message: str = "",
):
    docker_hosts, docker_totals = query_docker_containers(q=q, state=state, host=host)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "view": "docker",
            "docker_hosts": docker_hosts,
            "docker_totals": docker_totals,
            "docker_filters": {"q": q, "state": state, "host": host},
            "message": message,
        },
    )


@app.get("/systems")
def systems_view(
    request: Request,
    message: str = "",
    show_failures: int = 0,
):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "view": "systems",
            "systems": query_systems(bool(show_failures)),
            "show_failures": bool(show_failures),
            "ssh_scan_categories": SSH_SCAN_CATEGORIES,
            "message": message,
        },
    )


def query_devices() -> list[sqlite3.Row]:
    with db() as conn:
        return conn.execute(
            """
            SELECT
                d.device_id,
                d.logical_name,
                d.category,
                d.location,
                d.notes,
                COUNT(m.mac) AS interface_count,
                GROUP_CONCAT(m.mac, '\n') AS macs,
                GROUP_CONCAT(
                    CASE
                        WHEN m.current_ip <> '' THEN m.current_ip
                        ELSE NULL
                    END,
                    '\n'
                ) AS current_ips,
                GROUP_CONCAT(
                    CASE
                        WHEN m.reserved_ip <> '' THEN m.reserved_ip
                        ELSE NULL
                    END,
                    '\n'
                ) AS reserved_ips,
                GROUP_CONCAT(
                    CASE
                        WHEN m.hostname <> '' THEN m.hostname
                        ELSE NULL
                    END,
                    '\n'
                ) AS hostnames,
                MAX(m.last_seen) AS last_seen,
                COALESCE(sf.scan_status, '') AS scan_status,
                COALESCE(sf.scanned_at, '') AS scanned_at
            FROM devices d
            LEFT JOIN device_macs m
                ON m.device_id = d.device_id
            LEFT JOIN system_facts sf
                ON sf.device_id = d.device_id
            GROUP BY
                d.device_id,
                d.logical_name,
                d.category,
                d.location,
                d.notes,
                sf.scan_status,
                sf.scanned_at
            HAVING COUNT(m.mac) > 0
            ORDER BY
                CASE WHEN d.logical_name = '' THEN 1 ELSE 0 END,
                LOWER(d.logical_name),
                d.device_id
            """
        ).fetchall()


@app.get("/devices")
def devices_view(
    request: Request,
    message: str = "",
):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "view": "devices",
            "devices": query_devices(),
            "categories": CATEGORIES,
            "ssh_scan_categories": SSH_SCAN_CATEGORIES,
            "message": message,
        },
    )


@app.post("/devices/update/{device_id}")
def update_physical_device(
    device_id: str,
    logical_name: str = Form(""),
    category: str = Form("Unknown"),
    location: str = Form(""),
    notes: str = Form(""),
):
    with db() as conn:
        conn.execute(
            """
            UPDATE devices
            SET
                logical_name = ?,
                category = ?,
                location = ?,
                notes = ?
            WHERE device_id = ?
            """,
            (
                logical_name.strip(),
                category,
                location.strip(),
                notes.strip(),
                device_id,
            ),
        )

    return RedirectResponse(
        url="/devices?message=Device updated",
        status_code=303,
    )


@app.post("/link-device")
async def link_selected_macs(request: Request):
    form = await request.form()
    selected = [
        str(value).lower()
        for value in form.getlist("selected")
    ]

    if len(selected) < 2:
        return RedirectResponse(
            url="/?message=Select at least two MAC rows to link",
            status_code=303,
        )

    logical_name = str(form.get("link_logical_name", "")).strip()
    category = str(form.get("link_category", "")).strip()
    location = str(form.get("link_location", "")).strip()
    notes = str(form.get("link_notes", "")).strip()

    placeholders = ",".join("?" for _ in selected)

    with db() as conn:
        rows = conn.execute(
            f"""
            SELECT
                m.mac,
                m.device_id,
                d.logical_name,
                d.category,
                d.location,
                d.notes
            FROM device_macs m
            JOIN devices d
                ON d.device_id = m.device_id
            WHERE m.mac IN ({placeholders})
            ORDER BY m.mac
            """,
            selected,
        ).fetchall()

        if len(rows) < 2:
            return RedirectResponse(
                url="/?message=Selected MAC records were not found",
                status_code=303,
            )

        target_device_id = rows[0]["device_id"]
        old_device_ids = {
            row["device_id"]
            for row in rows
            if row["device_id"] != target_device_id
        }

        # Preserve existing metadata unless an explicit merge value is entered.
        target = rows[0]
        merged_name = logical_name or target["logical_name"]
        merged_category = category or target["category"] or "Unknown"
        merged_location = location or target["location"]
        merged_notes = notes or target["notes"]

        conn.execute(
            f"""
            UPDATE device_macs
            SET device_id = ?
            WHERE mac IN ({placeholders})
            """,
            [target_device_id, *selected],
        )

        conn.execute(
            """
            UPDATE devices
            SET
                logical_name = ?,
                category = ?,
                location = ?,
                notes = ?
            WHERE device_id = ?
            """,
            (
                merged_name,
                merged_category,
                merged_location,
                merged_notes,
                target_device_id,
            ),
        )

        for old_device_id in old_device_ids:
            remaining = conn.execute(
                """
                SELECT COUNT(*)
                FROM device_macs
                WHERE device_id = ?
                """,
                (old_device_id,),
            ).fetchone()[0]

            if remaining == 0:
                conn.execute(
                    """
                    DELETE FROM devices
                    WHERE device_id = ?
                    """,
                    (old_device_id,),
                )

    message = f"Linked {len(rows)} MAC records to one device"
    return RedirectResponse(
        url="/?message=" + requests.utils.quote(message),
        status_code=303,
    )


@app.get("/export.csv")
def export_inventory_csv(request: Request):
    params = request.query_params
    filters = {
        key: params.get(key, "")
        for key in [
            "q", "current_ip", "ip_source", "reserved_ip", "mac",
            "hostname", "unifi_name", "connection", "uplink",
            "unifi_model", "unifi_firmware", "unifi_state", "vendor",
            "type", "family", "os", "hardware_version",
            "software_version", "logical_name", "category", "location",
            "notes", "proposed_ip", "reservation_description",
            "reservation",
        ]
    }
    sort_by = params.get("sort_by", "current_ip")
    sort_order = params.get("sort_order", "asc")
    rows, _ = query_rows(filters, sort_by, sort_order)

    output = io.StringIO()
    writer = csv.writer(output)
    columns = [
        "current_ip", "ip_source", "reserved_ip", "mac", "hostname",
        "unifi_name", "unifi_connection_type", "unifi_uplink_name",
        "unifi_model", "unifi_firmware", "unifi_state", "vendor",
        "type", "family", "os", "hardware_version", "software_version",
        "logical_name", "category", "location", "notes", "proposed_ip",
        "reservation_description", "reservation_id", "reserved",
        "last_seen",
    ]
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row[column] for column in columns])

    output.seek(0)
    filename = datetime.now().strftime("inventory-%Y%m%d-%H%M%S.csv")
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


@app.post("/refresh")
def refresh():
    try:
        _, message = refresh_inventory()

    except Exception as exc:
        message = (
            f"Refresh failed: {exc}"
        )

    return RedirectResponse(
        url=(
            "/?message="
            f"{requests.utils.quote(message)}"
        ),
        status_code=303,
    )


@app.post("/update/{mac}")
def update_device(
    mac: str,
    logical_name: str = Form(""),
    category: str = Form("Unknown"),
    location: str = Form(""),
    notes: str = Form(""),
    proposed_ip: str = Form(""),
    proposed_description: str = Form(""),
):
    mac = mac.lower()

    with db() as conn:
        row = conn.execute(
            """
            SELECT device_id
            FROM device_macs
            WHERE mac=?
            """,
            (mac,),
        ).fetchone()

        if row:
            conn.execute(
                """
                UPDATE devices
                SET
                    logical_name=?,
                    category=?,
                    location=?,
                    notes=?
                WHERE device_id=?
                """,
                (
                    logical_name,
                    category,
                    location,
                    notes,
                    row["device_id"],
                ),
            )

            conn.execute(
                """
                UPDATE device_macs
                SET
                    proposed_ip=?,
                    proposed_description=?
                WHERE mac=?
                """,
                (
                    proposed_ip.strip(),
                    proposed_description.strip(),
                    mac,
                ),
            )

    return RedirectResponse(
        url="/",
        status_code=303,
    )


@app.post("/bulk-update")
async def bulk_update(
    request: Request,
):
    form = await request.form()

    selected = [
        str(value).lower()
        for value in form.getlist(
            "selected"
        )
    ]

    if not selected:
        return RedirectResponse(
            url="/?message=No rows selected",
            status_code=303,
        )

    bulk_category = str(
        form.get(
            "bulk_category",
            "",
        )
    ).strip()

    bulk_location = str(
        form.get(
            "bulk_location",
            "",
        )
    ).strip()

    bulk_notes = str(
        form.get(
            "bulk_notes",
            "",
        )
    ).strip()

    if not any(
        [
            bulk_category,
            bulk_location,
            bulk_notes,
        ]
    ):
        return RedirectResponse(
            url="/?message=No bulk values entered",
            status_code=303,
        )

    placeholders = ",".join(
        "?"
        for _ in selected
    )

    with db() as conn:
        device_rows = conn.execute(
            f"""
            SELECT DISTINCT device_id
            FROM device_macs
            WHERE mac IN (
                {placeholders}
            )
            """,
            selected,
        ).fetchall()

        updated = 0

        for device_row in device_rows:
            updates: list[str] = []
            values: list[Any] = []

            if bulk_category:
                updates.append(
                    "category=?"
                )
                values.append(
                    bulk_category
                )

            if bulk_location:
                updates.append(
                    "location=?"
                )
                values.append(
                    bulk_location
                )

            if bulk_notes:
                updates.append(
                    "notes=?"
                )
                values.append(
                    bulk_notes
                )

            if not updates:
                continue

            values.append(
                device_row["device_id"]
            )

            conn.execute(
                f"""
                UPDATE devices
                SET {", ".join(updates)}
                WHERE device_id=?
                """,
                values,
            )

            updated += 1

    message = (
        f"Bulk updated {updated} device records"
    )

    return RedirectResponse(
        url=(
            "/?message="
            f"{requests.utils.quote(message)}"
        ),
        status_code=303,
    )


def validate_selected(
    rows: list[sqlite3.Row],
) -> list[str]:
    errors: list[str] = []
    proposed_ips: dict[str, str] = {}

    with db() as conn:
        reserved_rows = conn.execute(
            """
            SELECT
                mac,
                reserved_ip
            FROM device_macs
            WHERE reserved_ip <> ''
            """
        ).fetchall()

    reserved_by_ip = {
        row["reserved_ip"]:
            row["mac"]
        for row in reserved_rows
    }

    for row in rows:
        proposed_ip = (
            row["proposed_ip"]
            or ""
        ).strip()

        if not proposed_ip:
            errors.append(
                f"{row['mac']}: "
                "proposed IP is blank"
            )
            continue

        try:
            ipaddress.ip_address(
                proposed_ip
            )

        except ValueError:
            errors.append(
                f"{row['mac']}: "
                f"invalid proposed IP "
                f"{proposed_ip}"
            )
            continue

        other_selected = proposed_ips.get(
            proposed_ip
        )

        if (
            other_selected
            and other_selected != row["mac"]
        ):
            errors.append(
                f"{proposed_ip}: selected for both "
                f"{other_selected} and "
                f"{row['mac']}"
            )

        proposed_ips[
            proposed_ip
        ] = row["mac"]

        existing_mac = reserved_by_ip.get(
            proposed_ip
        )

        if (
            existing_mac
            and existing_mac != row["mac"]
        ):
            errors.append(
                f"{proposed_ip}: already reserved "
                f"to {existing_mac}"
            )

    return errors


@app.post("/generate")
async def generate_changes(
    request: Request,
):
    form = await request.form()

    selected = [
        str(value).lower()
        for value in form.getlist(
            "selected"
        )
    ]

    if not selected:
        return RedirectResponse(
            url="/?message=No rows selected",
            status_code=303,
        )

    submitted_ips: dict[
        str,
        str,
    ] = {}

    submitted_descriptions: dict[
        str,
        str,
    ] = {}

    for value in form.getlist(
        "generated_proposed_ip"
    ):
        mac, separator, proposed_ip = (
            str(value).partition("|")
        )

        if separator:
            submitted_ips[
                mac.lower()
            ] = proposed_ip.strip()

    for value in form.getlist(
        "generated_description"
    ):
        mac, separator, description = (
            str(value).partition("|")
        )

        if separator:
            submitted_descriptions[
                mac.lower()
            ] = description.strip()

    placeholders = ",".join(
        "?"
        for _ in selected
    )

    with db() as conn:
        for selected_mac in selected:
            if selected_mac not in submitted_ips:
                continue

            conn.execute(
                """
                UPDATE device_macs
                SET
                    proposed_ip=?,
                    proposed_description=?
                WHERE mac=?
                """,
                (
                    submitted_ips.get(
                        selected_mac,
                        "",
                    ),
                    submitted_descriptions.get(
                        selected_mac,
                        "",
                    ),
                    selected_mac,
                ),
            )

        rows = conn.execute(
            f"""
            SELECT
                m.*,
                d.logical_name
            FROM device_macs m
            JOIN devices d
                ON d.device_id=m.device_id
            WHERE m.mac IN (
                {placeholders}
            )
            """,
            selected,
        ).fetchall()

        max_id = conn.execute(
            """
            SELECT
                COALESCE(
                    MAX(reservation_id),
                    0
                )
            FROM device_macs
            """
        ).fetchone()[0]

    errors = validate_selected(
        rows
    )

    if errors:
        message = " | ".join(
            errors
        )

        return RedirectResponse(
            url=(
                "/?message="
                f"{requests.utils.quote(message)}"
            ),
            status_code=303,
        )

    next_id = int(
        max_id
    ) + 1

    commands = [
        "config system dhcp server",
        f"    edit {DHCP_SERVER_ID}",
        "        config reserved-address",
    ]

    for row in sorted(
        rows,
        key=lambda item:
            item["proposed_ip"],
    ):
        reservation_id = int(
            row["reservation_id"]
            or 0
        )

        if reservation_id <= 0:
            reservation_id = next_id
            next_id += 1

        description = (
            (
                row["proposed_description"]
                or ""
            ).strip()
            or (
                row["logical_name"]
                or ""
            ).strip()
            or (
                row["unifi_name"]
                or ""
            ).strip()
            or (
                row["hostname"]
                or ""
            ).strip()
        ).replace(
            '"',
            "'",
        )

        commands.extend(
            [
                f"            edit "
                f"{reservation_id}",
                f"                set ip "
                f"{row['proposed_ip'].strip()}",
                f"                set mac "
                f"{row['mac']}",
                f'                set description '
                f'"{description}"',
                "            next",
            ]
        )

    commands.extend(
        [
            "        end",
            "    next",
            "end",
            "",
        ]
    )

    CHANGE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    CHANGE_FILE.write_text(
        "\n".join(commands),
        encoding="utf-8",
    )

    return FileResponse(
        CHANGE_FILE,
        media_type="text/plain",
        filename="fortigate-changes.cli",
    )


@app.post("/generate-removals")
async def generate_reservation_removals(request: Request):
    form = await request.form()
    selected = [
        str(value).lower()
        for value in form.getlist("selected")
    ]

    if not selected:
        return RedirectResponse(
            url="/?message=No rows selected",
            status_code=303,
        )

    placeholders = ",".join("?" for _ in selected)
    with db() as conn:
        rows = conn.execute(
            f"""
            SELECT mac, reservation_id, reserved_ip
            FROM device_macs
            WHERE mac IN ({placeholders})
              AND reserved=1
              AND reservation_id > 0
            ORDER BY reservation_id
            """,
            selected,
        ).fetchall()

    if not rows:
        return RedirectResponse(
            url="/?message=Selected rows have no removable reservations",
            status_code=303,
        )

    commands = [
        "config system dhcp server",
        f"    edit {DHCP_SERVER_ID}",
        "        config reserved-address",
    ]
    for row in rows:
        commands.append(f"            delete {int(row['reservation_id'])}")
    commands.extend([
        "        end",
        "    next",
        "end",
        "",
    ])

    removal_file = CHANGE_FILE.with_name("fortigate-removals.cli")
    removal_file.parent.mkdir(parents=True, exist_ok=True)
    removal_file.write_text("\n".join(commands), encoding="utf-8")

    return FileResponse(
        removal_file,
        media_type="text/plain",
        filename="fortigate-removals.cli",
    )


@app.get("/changes")
def download_changes():
    if not CHANGE_FILE.exists():
        return RedirectResponse(
            url=(
                "/?message="
                "No generated change file exists"
            ),
            status_code=303,
        )

    return FileResponse(
        CHANGE_FILE,
        media_type="text/plain",
        filename="fortigate-changes.cli",
    )
