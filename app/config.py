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

    # Outbound SMTP for the "Angebot per E-Mail senden" feature.
    # Leave empty to disable the send-email button (button shows mailto:-fallback).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True     # STARTTLS on 587
    smtp_use_ssl: bool = False    # implicit TLS on 465
    mail_from_address: str = "daniel.rupp@zdkg.de"
    mail_from_name: str = "ZDKG — Advanced Analytics GmbH"
    mail_reply_to: str = "daniel.rupp@zdkg.de"

    # Inbound mail (IMAP). Same account as SMTP by default — Gmail supports both
    # over the same app-password. Leave imap_host empty to disable inbox polling.
    imap_host: str = "imap.gmail.com"
    imap_port: int = 993
    imap_user: str = ""                 # defaults to smtp_user at runtime when empty
    imap_password: str = ""             # defaults to smtp_password at runtime when empty
    imap_folder: str = "INBOX"
    imap_poll_seconds: int = 120
    imap_lookback_days: int = 60        # initial backfill window on first poll

    # LLM for AI-drafted reply suggestions on the message detail view.
    # llm_provider: "anthropic" or "openai" (leave empty to disable — UI falls back to a plain template).
    llm_provider: str = "anthropic"
    llm_api_key: str = ""
    llm_model: str = "claude-haiku-4-5-20251001"
    llm_max_tokens: int = 1500


@lru_cache
def get_settings() -> Settings:
    return Settings()
