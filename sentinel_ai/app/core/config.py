from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import List


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Sentinel AI"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    API_V1_PREFIX: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = "postgresql://sentinel:sentinel_pass@localhost:5432/sentinel_ai"
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Security
    SECRET_KEY: str = "your-super-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # ML Models
    MODEL_PATH: str = "./models/trained"
    DDOS_MODEL_PATH: str = "./models/ddos_model.pkl"
    MALWARE_MODEL_PATH: str = "./models/malware_cnn.h5"
    SQLI_MODEL_PATH: str = "./models/sqli_model.pkl"
    BRUTEFORCE_MODEL_PATH: str = "./models/bruteforce_model.pkl"
    
    # Detection Thresholds
    DDOS_THRESHOLD: float = 0.85
    MALWARE_THRESHOLD: float = 0.75
    SQLI_THRESHOLD: float = 0.80
    BRUTEFORCE_THRESHOLD: float = 0.70
    ANOMALY_THRESHOLD: float = 0.75
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    LOGIN_ATTEMPT_THRESHOLD: int = 5
    TIME_WINDOW_SECONDS: int = 300
    
    # Alerting
    ALERT_EMAIL: str = "admin@example.com"
    SLACK_WEBHOOK_URL: str = ""
    ENABLE_EMAIL_ALERTS: bool = False
    
    # Performance
    MAX_CONCURRENT_REQUESTS: int = 100
    REQUEST_TIMEOUT_SECONDS: int = 30
    BATCH_SIZE: int = 32
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
