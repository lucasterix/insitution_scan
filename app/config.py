from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    secret_key: str = "change-me"
    database_url: str = "postgresql+asyncpg://scan:scan@postgres:5432/scan"
    redis_url: str = "redis://redis:6379/0"
    public_base_url: str = "http://localhost:8000"
    log_level: str = "INFO"

    # Optional third-party API keys — scanners gracefully skip when empty.
    shodan_api_key: str = ""
    hibp_api_key: str = ""  # deprecated in favour of leakcheck; kept for future
    leakcheck_api_key: str = ""
    otx_api_key: str = ""
    abuseipdb_api_key: str = ""
    nvd_api_key: str = ""  # optional; NVD works without but gives higher rate limit
    securitytrails_api_key: str = ""
    virustotal_api_key: str = ""
    hunter_api_key: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
