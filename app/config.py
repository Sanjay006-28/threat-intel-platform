import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "changeme123"
    SECRET_KEY: str = "supersecretkey-sentinel-cti-platform-local-soc"
    DEV_AUTO_LOGIN: bool = False  # Secure by default: requires authentication
    
    SESSION_MAX_AGE_SECONDS: int = 86400 # 24 hours session expiry
    HOST: str = "127.0.0.1" # Bind to localhost by default for local-only safety
    PORT: int = 8000
    
    OTX_API_KEY: str = ""
    
    IOC_TTL_DAYS: int = 30
    SCHEDULER_INTERVAL_MINUTES: int = 360 # Default 6 hours feed sync interval
    
    # Database and directories
    DATABASE_URL: str = "sqlite:///./threat_intel.db"
    AUTO_INGEST_DIR: str = "./auto_ingest"
    ALERT_WEBHOOK_URL: str = ""
    
    # Enrichment and correlation settings
    GEOIP_DB_PATH: str = "./GeoLite2-City.mmdb"
    DEDUPLICATION_WINDOW_MINUTES: int = 60 # 1 hour aggregation window
    BATCH_SIZE: int = 500 # Log processing transaction batch size

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
