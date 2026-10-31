from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class IOC(Base):
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    type = Column(String(50), nullable=False, index=True) # ipv4, ipv6, cidr, domain, url, email, md5, sha1, sha256
    value = Column(String(1024), nullable=False, unique=True, index=True)
    confidence = Column(Integer, default=50) # 0-100
    severity = Column(String(20), default="medium") # low, medium, high, critical
    tags = Column(JSON, default=list)
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    description = Column(Text, nullable=True)

    sources = relationship("IOCSource", back_populates="ioc", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="ioc")


class IOCSource(Base):
    __tablename__ = "ioc_sources"
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    feed_name = Column(String(100), nullable=False)
    reference_url = Column(String(1024), nullable=True)
    seen_at = Column(DateTime, default=utcnow)
    
    ioc = relationship("IOC", back_populates="sources")


class Feed(Base):
    __tablename__ = "feeds"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    type = Column(String(50), nullable=False) # api, file, etc.
    enabled = Column(Boolean, default=True)
    interval_minutes = Column(Integer, default=360)
    last_run_status = Column(String(50), nullable=True)
    last_run_at = Column(DateTime, nullable=True)
    
    runs = relationship("FeedRun", back_populates="feed", cascade="all, delete-orphan")


class FeedRun(Base):
    __tablename__ = "feed_runs"
    
    id = Column(Integer, primary_key=True, index=True)
    feed_id = Column(Integer, ForeignKey("feeds.id"), nullable=False)
    start_time = Column(DateTime, default=utcnow)
    end_time = Column(DateTime, nullable=True)
    status = Column(String(50), nullable=False) # success, failed, processing
    records_fetched = Column(Integer, default=0)
    new_records = Column(Integer, default=0)
    updated_records = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    
    feed = relationship("Feed", back_populates="runs")


class LogFile(Base):
    __tablename__ = "log_files"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    type = Column(String(50), nullable=False)
    uploaded_at = Column(DateTime, default=utcnow)
    line_count = Column(Integer, default=0)
    status = Column(String(50), nullable=False) # processing, done, error
    
    events = relationship("LogEvent", back_populates="log_file", cascade="all, delete-orphan")


class LogEvent(Base):
    __tablename__ = "log_events"
    
    id = Column(Integer, primary_key=True, index=True)
    log_file_id = Column(Integer, ForeignKey("log_files.id"), nullable=False)
    timestamp = Column(DateTime, nullable=True)
    raw_line = Column(Text, nullable=False)
    extracted_artifacts = Column(JSON, default=list) # List of dicts
    
    log_file = relationship("LogFile", back_populates="events")
    alerts = relationship("Alert", back_populates="log_event")


class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), default="medium") # low, medium, high, critical
    status = Column(String(50), default="open") # open, investigating, contained, resolved, closed
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    analyst_notes = Column(Text, nullable=True)
    resolution_summary = Column(Text, nullable=True)

    alerts = relationship("Alert", back_populates="incident")


class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    log_event_id = Column(Integer, ForeignKey("log_events.id"), nullable=False)
    matched_value = Column(String(1024), nullable=False)
    matched_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    score = Column(Integer, default=0)
    status = Column(String(50), default="new") # new, investigating, resolved, false_positive
    analyst_note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    hit_count = Column(Integer, default=1)
    dedupe_key = Column(String(255), unique=True, index=True, nullable=False)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    
    ioc = relationship("IOC", back_populates="alerts")
    log_event = relationship("LogEvent", back_populates="alerts")
    incident = relationship("Incident", back_populates="alerts")


class Whitelist(Base):
    __tablename__ = "whitelist"
    
    id = Column(Integer, primary_key=True, index=True)
    type = Column(String(50), nullable=False)
    value = Column(String(1024), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    reason = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utcnow)


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst") # admin, analyst
    created_at = Column(DateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    user = Column(String(100), default="system", index=True)
    action = Column(String(100), nullable=False, index=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)
