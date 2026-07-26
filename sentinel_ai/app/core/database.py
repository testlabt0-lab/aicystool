from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import json

Base = declarative_base()


class DetectionLog(Base):
    __tablename__ = "detection_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    detection_type = Column(String(50), index=True)  # ddos, malware, sqli, bruteforce, log_analysis
    input_data = Column(JSON)
    prediction = Column(String(20))  # malicious, benign, suspicious
    confidence_score = Column(Float)
    risk_level = Column(String(20))  # low, medium, high, critical
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    metadata = Column(JSON)
    alerted = Column(Boolean, default=False)
    
    def to_dict(self):
        return {
            "id": self.id,
            "detection_type": self.detection_type,
            "prediction": self.prediction,
            "confidence_score": self.confidence_score,
            "risk_level": self.risk_level,
            "timestamp": self.timestamp.isoformat(),
            "ip_address": self.ip_address,
            "metadata": self.metadata
        }


class NetworkTraffic(Base):
    __tablename__ = "network_traffic"
    
    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45))
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(20))
    packet_size = Column(Integer)
    packets_per_second = Column(Float)
    bytes_per_second = Column(Float)
    flags = Column(String(100))
    is_attack = Column(Boolean, default=False)
    attack_type = Column(String(50))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), index=True)
    ip_address = Column(String(45), index=True)
    user_agent = Column(String(500))
    success = Column(Boolean)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    failure_count = Column(Integer, default=0)
    is_suspicious = Column(Boolean, default=False)
    
    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "ip_address": self.ip_address,
            "success": self.success,
            "timestamp": self.timestamp.isoformat(),
            "is_suspicious": self.is_suspicious
        }


class MalwareScan(Base):
    __tablename__ = "malware_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    file_name = Column(String(255))
    file_hash = Column(String(64), index=True)  # SHA256
    file_size = Column(Integer)
    scan_result = Column(String(20))  # clean, infected, suspicious
    confidence_score = Column(Float)
    malware_family = Column(String(100))
    scan_duration_ms = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": self.id,
            "file_name": self.file_name,
            "file_hash": self.file_hash,
            "scan_result": self.scan_result,
            "confidence_score": self.confidence_score,
            "malware_family": self.malware_family,
            "scan_duration_ms": self.scan_duration_ms,
            "timestamp": self.timestamp.isoformat()
        }


class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(50), index=True)
    severity = Column(String(20))  # info, warning, error, critical
    title = Column(String(255))
    description = Column(Text)
    source_ip = Column(String(45))
    detection_id = Column(Integer)
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(100))
    acknowledged_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            "id": self.id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "acknowledged": self.acknowledged,
            "created_at": self.created_at.isoformat()
        }


# Database connection
engine = create_engine(
    "postgresql://sentinel:sentinel_pass@localhost:5432/sentinel_ai",
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
