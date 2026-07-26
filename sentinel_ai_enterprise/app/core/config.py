# Core Configuration for Sentinel AI Enterprise

from pydantic import BaseSettings, Field
from typing import List, Optional
import os

class Settings(BaseSettings):
    """إعدادات النظام الأساسية"""
    
    # === إعدادات التطبيق ===
    APP_NAME: str = "Sentinel AI Enterprise"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"  # development, staging, production
    
    # === إعدادات الخادم ===
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4
    MAX_CONNECTIONS: int = 1000
    
    # === إعدادات قاعدة البيانات ===
    DATABASE_URL: str = Field(
        default="postgresql://sentinel:password@localhost:5432/sentinel_db",
        env="DATABASE_URL"
    )
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    
    # === إعدادات Redis ===
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        env="REDIS_URL"
    )
    REDIS_CACHE_TTL: int = 3600  # seconds
    
    # === إعدادات Kafka ===
    KAFKA_BOOTSTRAP_SERVERS: List[str] = ["localhost:9092"]
    KAFKA_TOPIC_TRAFFIC: str = "network-traffic"
    KAFKA_TOPIC_LOGS: str = "security-logs"
    KAFKA_TOPIC_ALERTS: str = "security-alerts"
    
    # === إعدادات الذكاء الاصطناعي ===
    ML_MODEL_PATH: str = "./data/models"
    ML_BATCH_SIZE: int = 32
    ML_INFERENCE_THREADS: int = 4
    ML_CONFIDENCE_THRESHOLD: float = 0.85
    
    # === DDoS Detection ===
    DDOS_WINDOW_SIZE: int = 60  # seconds
    DDOS_THRESHOLD_RPS: int = 10000  # requests per second
    DDOS_AUTO_MITIGATION: bool = True
    DDOS_CLOUDFLARE_API_KEY: Optional[str] = None
    DDOS_AWS_SHIELD_ENABLED: bool = False
    
    # === Malware Detection ===
    MALWARE_MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
    MALWARE_SANDBOX_ENABLED: bool = True
    MALWARE_YARA_RULES_PATH: str = "./configs/yara_rules"
    
    # === SQL Injection Detection ===
    SQLI_NLP_MODEL: str = "bert-base-uncased"
    SQLI_WAF_INTEGRATION: bool = True
    SQLI_BLOCK_MODE: bool = True  # True=block, False=log only
    
    # === Brute Force Detection ===
    BRUTE_FORCE_MAX_ATTEMPTS: int = 5
    BRUTE_FORCE_WINDOW: int = 300  # seconds
    BRUTE_FORCE_LOCKOUT_DURATION: int = 1800  # seconds
    BRUTE_FORCE_MFA_TRIGGER: bool = True
    
    # === Log Analysis ===
    LOG_RETENTION_DAYS: int = 90
    LOG_BATCH_PROCESSING_SIZE: int = 10000
    LOG_REAL_TIME_ENABLED: bool = True
    
    # === Threat Intelligence ===
    THREAT_INTEL_ENABLED: bool = True
    THREAT_INTEL_SOURCES: List[str] = [
        "misp",
        "alienvault_otx",
        "abuse_ch",
        "virustotal"
    ]
    THREAT_INTEL_UPDATE_INTERVAL: int = 3600  # seconds
    
    # === SOAR (Security Orchestration) ===
    SOAR_ENABLED: bool = True
    SOAR_PLAYBOOKS_PATH: str = "./configs/playbooks"
    SOAR_JIRA_URL: Optional[str] = None
    SOAR_SERVICENOW_URL: Optional[str] = None
    
    # === الأمان ===
    SECRET_KEY: str = Field(..., env="SECRET_KEY")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ENCRYPTION_KEY: str = Field(..., env="ENCRYPTION_KEY")
    
    # === RBAC ===
    RBAC_ENABLED: bool = True
    ADMIN_EMAILS: List[str] = ["admin@company.com"]
    
    # === المراقبة والتنبيهات ===
    MONITORING_ENABLED: bool = True
    PROMETHEUS_ENDPOINT: str = "/metrics"
    GRAFANA_URL: Optional[str] = None
    
    ALERT_EMAIL_ENABLED: bool = True
    ALERT_SMTP_SERVER: str = "smtp.company.com"
    ALERT_SMTP_PORT: int = 587
    ALERT_EMAIL_FROM: str = "alerts@sentinel.ai"
    ALERT_EMAIL_TO: List[str] = ["soc@company.com"]
    
    ALERT_SLACK_ENABLED: bool = False
    ALERT_SLACK_WEBHOOK: Optional[str] = None
    
    ALERT_TEAMS_ENABLED: bool = False
    ALERT_TEAMS_WEBHOOK: Optional[str] = None
    
    ALERT_PAGERDUTY_ENABLED: bool = False
    ALERT_PAGERDUTY_KEY: Optional[str] = None
    
    # === الأداء ===
    RATE_LIMIT_PER_SECOND: int = 1000
    RATE_LIMIT_PER_MINUTE: int = 50000
    CACHE_ENABLED: bool = True
    COMPRESSION_ENABLED: bool = True
    
    # === السجلات ===
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # json, text
    LOG_FILE: str = "./data/logs/sentinel.log"
    LOG_MAX_SIZE: int = 100  # MB
    LOG_BACKUP_COUNT: int = 10
    
    # === CORS ===
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "https://dashboard.sentinel.ai"
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# إنشاء نسخة من الإعدادات
settings = Settings()
