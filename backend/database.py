from datetime import datetime
from decouple import config
from sqlalchemy import (
    create_engine, Column, Integer, Text, Boolean,
    DateTime, UniqueConstraint, select, update, insert
)
from sqlalchemy.orm import declarative_base, Session

db_url = (
    f"postgresql+psycopg2://{config('DB_USER', default='postgres')}:"
    f"{config('DB_PASSWORD')}@{config('DB_HOST', default='localhost')}:"
    f"{config('DB_PORT', default=5432)}/{config('DB_NAME', default='netwatch')}"
)

engine = create_engine(db_url)
Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    ip = Column(Text, nullable=False, unique=True)
    mac = Column(Text)
    hostname = Column(Text)
    vendor = Column(Text)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    online = Column(Boolean, default=True)


class PortScan(Base):
    __tablename__ = "port_scans"
    id = Column(Integer, primary_key=True)
    ip = Column(Text, nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(Text)
    service = Column(Text)
    scanned_at = Column(DateTime, default=datetime.utcnow)


class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True)
    ip = Column(Text, nullable=False)
    hostname = Column(Text)
    event_type = Column(Text, nullable=False)
    detail = Column(Text)
    occurred_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(engine)


def log_event(ip, hostname, event_type, detail, session=None):
    close = session is None
    if close:
        session = Session(engine)
    session.add(Event(ip=ip, hostname=hostname, event_type=event_type, detail=detail))
    if close:
        session.commit()
        session.close()


def upsert_device(ip, mac=None, hostname=None, vendor=None):
    with Session(engine) as session:
        device = session.scalar(select(Device).where(Device.ip == ip))
        if device:
            was_offline = not device.online
            device.last_seen = datetime.utcnow()
            device.online = True
            if mac:
                device.mac = mac
            if hostname:
                device.hostname = hostname
            if vendor:
                device.vendor = vendor
            if was_offline:
                log_event(ip, hostname or device.hostname, "came_online", "device back online", session)
        else:
            session.add(Device(ip=ip, mac=mac, hostname=hostname, vendor=vendor))
            log_event(ip, hostname, "discovered", "new device discovered", session)
        session.commit()


def mark_offline(ip):
    with Session(engine) as session:
        device = session.scalar(select(Device).where(Device.ip == ip, Device.online == True))
        if device:
            device.online = False
            log_event(ip, device.hostname, "went_offline", "device no longer responding", session)
        session.commit()


def upsert_ports(ip, ports: list[dict]):
    with Session(engine) as session:
        prev_ports = set(
            row.port for row in
            session.scalars(select(PortScan.port).where(PortScan.ip == ip)).all()
        )
        new_ports = set(p["port"] for p in ports)

        for p in ports:
            session.add(PortScan(
                ip=ip,
                port=p["port"],
                protocol=p.get("protocol", "tcp"),
                service=p.get("service", "")
            ))

        device = session.scalar(select(Device).where(Device.ip == ip))
        hostname = device.hostname if device else None

        opened = new_ports - prev_ports
        closed = prev_ports - new_ports

        for port in opened:
            log_event(ip, hostname, "port_opened", f"port {port} opened", session)
        for port in closed:
            log_event(ip, hostname, "port_closed", f"port {port} closed", session)

        session.commit()
    return list(opened), list(closed)


def get_all_online_devices():
    with Session(engine) as session:
        return session.scalars(select(Device).where(Device.online == True)).all()


def get_all_devices():
    with Session(engine) as session:
        return session.scalars(select(Device).order_by(Device.online.desc(), Device.last_seen.desc())).all()