import asyncio
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from decouple import config
from database import init_db, upsert_device, mark_offline, upsert_ports, get_conn

SUBNET = config("NETWORK_SUBNET", default="192.168.1.0/24")
SCAN_INTERVAL = int(config("SCAN_INTERVAL", default=300))


def parse_nmap_xml(xml_output: str) -> list[dict]:
    devices = []
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            ip, mac, vendor = None, None, None
            for a in host.findall("address"):
                if a.get("addrtype") == "ipv4":
                    ip = a.get("addr")
                elif a.get("addrtype") == "mac":
                    mac = a.get("addr")
                    vendor = a.get("vendor", "")

            hostname = None
            hostnames = host.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    hostname = hn.get("name")

            ports = []
            ports_el = host.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state = port_el.find("state")
                    if state is not None and state.get("state") == "open":
                        service = port_el.find("service")
                        ports.append({
                            "port": int(port_el.get("portid")),
                            "protocol": port_el.get("protocol", "tcp"),
                            "service": service.get("name", "") if service is not None else ""
                        })

            if ip:
                devices.append({
                    "ip": ip, "mac": mac, "vendor": vendor,
                    "hostname": hostname, "ports": ports
                })
    except Exception as e:
        print(f"nmap parse error: {e}")
    return devices


def run_scan(subnet: str) -> list[dict]:
    try:
        result = subprocess.run(
            ["sudo", "nmap", "-sS", "-O", "--open", "-oX", "-", subnet],
            capture_output=True, text=True, timeout=120
        )
        return parse_nmap_xml(result.stdout)
    except subprocess.TimeoutExpired:
        print("nmap scan timed out")
        return []
    except FileNotFoundError:
        print("nmap not found, install with: sudo apt install nmap")
        return []
    except Exception as e:
        print(f"scan error: {e}")
        return []


async def scan_loop(notify_callback=None):
    init_db()
    print(f"netwatch scanner started, scanning {SUBNET} every {SCAN_INTERVAL}s")

    while True:
        print(f"[{datetime.utcnow().isoformat()}] scanning {SUBNET}")
        devices = run_scan(SUBNET)
        seen_ips = set()

        for device in devices:
            ip = device["ip"]
            seen_ips.add(ip)
            upsert_device(ip, device["mac"], device["hostname"], device["vendor"])

            if device["ports"]:
                opened, closed = upsert_ports(ip, device["ports"])
                if notify_callback and (opened or closed):
                    name = device["hostname"] or ip
                    if opened:
                        await notify_callback(f"{name}: new ports opened: {', '.join(map(str, opened))}")
                    if closed:
                        await notify_callback(f"{name}: ports closed: {', '.join(map(str, closed))}")

        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT ip, hostname FROM devices WHERE online = TRUE")
        online_devices = cur.fetchall()
        cur.close()
        conn.close()

        for row in online_devices:
            if row["ip"] not in seen_ips:
                mark_offline(row["ip"])
                if notify_callback:
                    name = row["hostname"] or row["ip"]
                    await notify_callback(f"{name} ({row['ip']}) went offline")

        if notify_callback and devices:
            conn = get_conn()
            cur = conn.cursor()
            for ip in seen_ips:
                cur.execute("SELECT * FROM devices WHERE ip = %s AND first_seen = last_seen", (ip,))
                d = cur.fetchone()
                if d:
                    name = d["hostname"] or d["ip"]
                    await notify_callback(f"new device discovered: {name} ({d['ip']})")
            cur.close()
            conn.close()

        print(f"scan complete, {len(devices)} devices found")
        await asyncio.sleep(SCAN_INTERVAL)