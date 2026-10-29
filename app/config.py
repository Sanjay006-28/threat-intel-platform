import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "changeme123"
    SECRET_KEY: str = "supersecretkey"
    DEV_AUTO_LOGIN: bool = True  # Set to False to enforce login authentication
    
    OTX_API_KEY: str = ""
    
    IOC_TTL_DAYS: int = 30
    SCHEDULER_INTERVAL_MINUTES: int = 360
    
    DATABASE_URL: str = "sqlite:///./threat_intel.db"
    AUTO_INGEST_DIR: str = "./auto_ingest"
    ALERT_WEBHOOK_URL: str = ""

    class Config:
        env_file = ".env"

settings = Settings()
