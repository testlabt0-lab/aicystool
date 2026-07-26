"""
Sentinel AI - Advanced Cybersecurity Detection System
Production-Ready Configuration with Advanced Features
"""

import os
from pydantic import BaseSettings, validator
from typing import List, Optional
import secrets

class Settings(BaseSettings):
    """Advanced system configuration with security features"""
    
    # Application Settings
    APP_NAME: str = "Sentinel AI Security Platform"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"
    
    # API Settings
    API_PREFIX: str = "/api/v2"
    API_RATE_LIMIT: int = 1000  # requests per minute
    API_TIMEOUT: int = 30  # seconds
    MAX_PAYLOAD_SIZE: int = 10 * 1024 * 1024  # 10MB
    
    # Security Settings
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "https://sentinel.local"]
    
    # Database Settings
    DATABASE_URL: str = "postgresql://sentinel:sentinel_pass@postgres:5432/sentinel_db"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    DATABASE_POOL_TIMEOUT: int = 30
    
    # Redis Settings
    REDIS_URL: str = "redis://redis:6379/0"
    REDIS_CACHE_TTL: int = 300  # 5 minutes
    REDIS_SESSION_TTL: int = 3600  # 1 hour
    
    # ML Model Settings
    MODEL_PATH: str = "./app/models/trained"
    MODEL_AUTO_UPDATE: bool = True
    MODEL_CONFIDENCE_THRESHOLD: float = 0.85
    MODEL_BATCH_SIZE: int = 32
    MODEL_INFERENCE_THREADS: int = 4
    
    # DDoS Detection Settings
    DDOS_WINDOW_SIZE: int = 60  # seconds
    DDOS_THRESHOLD_RPS: int = 10000  # requests per second
    DDOS_THRESHOLD_PACKETS: int = 50000  # packets per second
    DDOS_IP_BLACKLIST_DURATION: int = 3600  # seconds
    
    # Malware Detection Settings
    MALWARE_MAX_FILE_SIZE: int = 50 * 1024 * 1024  # 50MB
    MALWARE_SCAN_TIMEOUT: int = 120  # seconds
    MALWARE_QUARANTINE_ENABLED: bool = True
    MALWARE_QUARANTINE_PATH: str = "./quarantine"
    
    # SQL Injection Settings
    SQLI_PATTERN_MATCHING: bool = True
    SQLI_ML_DETECTION: bool = True
    SQLI_BLOCK_IMMEDIATELY: bool = False
    SQLI_LOG_ALL_ATTEMPTS: bool = True
    
    # Brute Force Settings
    BRUTE_FORCE_MAX_ATTEMPTS: int = 5
    BRUTE_FORCE_WINDOW: int = 300  # seconds
    BRUTE_FORCE_LOCKOUT_DURATION: int = 900  # 15 minutes
    BRUTE_FORCE_WHITELIST_IPS: List[str] = []
    
    # Log Analysis Settings
    LOG_RETENTION_DAYS: int = 90
    LOG_REAL_TIME_ANALYSIS: bool = True
    LOG_ALERT_THRESHOLD: int = 10  # anomalies per minute
    LOG_STORAGE_PATH: str = "./logs/archived"
    
    # Alerting Settings
    ALERT_EMAIL_ENABLED: bool = True
    ALERT_EMAIL_SMTP_SERVER: str = "smtp.gmail.com"
    ALERT_EMAIL_SMTP_PORT: int = 587
    ALERT_EMAIL_SENDER: str = "alerts@sentinel.local"
    ALERT_EMAIL_RECIPIENTS: List[str] = ["security@company.com"]
    
    ALERT_SLACK_ENABLED: bool = True
    ALERT_SLACK_WEBHOOK_URL: str = ""
    ALERT_SLACK_CHANNEL: str = "#security-alerts"
    
    ALERT_PAGERDUTY_ENABLED: bool = False
    ALERT_PAGERDUTY_SERVICE_KEY: str = ""
    
    # WebSocket Settings
    WS_HEARTBEAT_INTERVAL: int = 30  # seconds
    WS_MAX_CONNECTIONS: int = 1000
    WS_MESSAGE_QUEUE_SIZE: int = 1000
    
    # Monitoring & Metrics
    METRICS_ENABLED: bool = True
    METRICS_PROMETHEUS_PORT: int = 9090
    HEALTH_CHECK_INTERVAL: int = 10  # seconds
    TRACING_ENABLED: bool = True
    TRACING_JAEGER_ENDPOINT: str = "http://jaeger:14268/api/traces"
    
    # Advanced Features
    AUTO_MITIGATION_ENABLED: bool = True
    THREAT_INTELLIGENCE_FEED: bool = True
    THREAT_INTEL_URLS: List[str] = [
        "https://threatfeeds.example.com/malicious_ips",
        "https://threatfeeds.example.com/malware_hashes"
    ]
    BEHAVIORAL_ANALYSIS_ENABLED: bool = True
    ANOMALY_DETECTION_SENSITIVITY: float = 0.75
    
    # Performance Settings
    WORKER_PROCESSES: int = 4
    THREADS_PER_WORKER: int = 2
    ASYNC_IO_ENABLED: bool = True
    COMPRESSION_ENABLED: bool = True
    COMPRESSION_LEVEL: int = 6
    
    # Backup & Recovery
    BACKUP_ENABLED: bool = True
    BACKUP_INTERVAL_HOURS: int = 6
    BACKUP_STORAGE_PATH: str = "./backups"
    BACKUP_RETENTION_COUNT: int = 10
    
    @validator('SECRET_KEY')
    def validate_secret_key(cls, v):
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v
    
    @validator('ENVIRONMENT')
    def validate_environment(cls, v):
        allowed = ['development', 'staging', 'production']
        if v not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of {allowed}")
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Global settings instance
settings = Settings()
