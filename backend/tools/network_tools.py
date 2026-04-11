import subprocess
import os
from datetime import datetime, timedelta
from langchain_core.tools import tool
from sqlalchemy import select
from sqlalchemy.orm import Session



from database import engine, Device, Event, get_all_devices
from scanner import run_scan, SUBNET


@tool
def scan_network(subnet: str = "") -> str:
    """
    Runs a fresh nmap scan on the network and returns all live hosts with open ports.
    subnet: optional subnet to scan e.g. 192.168.1.0/24 (defaults to configured subnet)
    """
    target = subnet or SUBNET
    devices = run_scan(target)
    if not devices:
        return "no devices found or nmap is not available"
    lines = []
    for d in devices:
        ports = ", ".join(str(p["port"]) for p in d["ports"]) if d["ports"] else "no open ports"
        name = d["hostname"] or d["ip"]
        lines.append(f"{name} ({d['ip']}): {ports}")
    return "\n".join(lines)


@tool
def get_known_devices() -> str:
    """Returns all known devices from the database with their status and last seen time"""
    devices = get_all_devices()
    if not devices:
        return "no devices in database yet, run a scan first"
    lines = []
    for d in devices:
        status = "online" if d.online else "offline"
        name = d.hostname or d.ip
        vendor = f" ({d.vendor})" if d.vendor else ""
        lines.append(f"{status}  {name} {d.ip}{vendor}  last seen {d.last_seen}")
    return "\n".join(lines)


@tool
def get_device_history(ip: str) -> str:
    """
    Shows the online/offline history for a specific device.
    ip: IP address of the device
    """
    with Session(engine) as session:
        events = session.scalars(
            select(Event).where(Event.ip == ip).order_by(Event.occurred_at.desc()).limit(50)
        ).all()
        device = session.scalar(select(Device).where(Device.ip == ip))

    if not events:
        return f"no history found for {ip}"

    name = device.hostname if device else ip
    lines = [f"history for {name} ({ip}):"]
    for e in events:
        lines.append(f"  {e.occurred_at}  {e.event_type}: {e.detail}")
    return "\n".join(lines)


@tool
def get_port_changes(since_hours: int = 24) -> str:
    """
    Shows any ports that opened or closed in the last N hours.
    since_hours: how many hours back to look (default 24)
    """
    since = datetime.utcnow() - timedelta(hours=since_hours)
    with Session(engine) as session:
        events = session.scalars(
            select(Event)
            .where(Event.event_type.in_(["port_opened", "port_closed"]), Event.occurred_at > since)
            .order_by(Event.occurred_at.desc())
        ).all()

    if not events:
        return f"no port changes in the last {since_hours} hours"

    lines = []
    for e in events:
        name = e.hostname or e.ip
        action = "opened" if e.event_type == "port_opened" else "closed"
        lines.append(f"{name} ({e.ip})  port {action}  {e.occurred_at}")
    return "\n".join(lines)


@tool
def get_offline_devices() -> str:
    """Shows all devices that are currently offline"""
    with Session(engine) as session:
        devices = session.scalars(
            select(Device).where(Device.online == False).order_by(Device.last_seen.desc())
        ).all()

    if not devices:
        return "all known devices are currently online"

    lines = []
    for d in devices:
        name = d.hostname or d.ip
        lines.append(f"offline  {name} ({d.ip})  last seen {d.last_seen}")
    return "\n".join(lines)


@tool
def whois_device(ip: str) -> str:
    """
    Tries to identify a device by running a detailed nmap scan and checking MAC vendor.
    ip: IP address to identify
    """
    try:
        result = subprocess.run(
            ["sudo", "nmap", "-sV", "-O", "--osscan-guess", ip],
            capture_output=True, text=True, timeout=60
        )
        with Session(engine) as session:
            device = session.scalar(select(Device).where(Device.ip == ip))

        output = result.stdout.strip()
        if device:
            output += f"\nstored info: hostname={device.hostname}, mac={device.mac}, vendor={device.vendor}"
        return output
    except Exception as e:
        return f"error: {e}"


@tool
def get_recent_events(since_hours: int = 24) -> str:
    """
    Shows all network events in the last N hours.
    since_hours: how many hours back to look (default 24)
    """
    since = datetime.utcnow() - timedelta(hours=since_hours)
    with Session(engine) as session:
        events = session.scalars(
            select(Event).where(Event.occurred_at > since).order_by(Event.occurred_at.desc())
        ).all()

    if not events:
        return f"no events in the last {since_hours} hours"

    lines = []
    for e in events:
        name = e.hostname or e.ip
        lines.append(f"{e.occurred_at}  {name} ({e.ip}): {e.detail}")
    return "\n".join(lines)