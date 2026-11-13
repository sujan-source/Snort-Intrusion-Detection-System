import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Intrusion Detection System Using Snort"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Secret Key for JWT Signing
    SECRET_KEY: str = "snort_nids_soc_super_secret_key_2026_antigravity"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 # 24 hours
    
    # Database
    DATABASE_URL: str = "sqlite:///./snort_nids.db"
    
    # Snort Log File Paths
    SNORT_ALERT_FILE: str = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "snort.alert")
    SNORT_RULES_FILE: str = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "rules", "local.rules")

    class Config:
        case_sensitive = True

settings = Settings()
