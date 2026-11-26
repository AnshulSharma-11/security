from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All configuration comes from environment variables (SENTINEL_*). No secrets live in code."""
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    secret_key: str  # required: no default on purpose
    database_url: str = "sqlite:///./sentinel.db"
    redis_url: str = "redis://localhost:6379/0"
    access_minutes: int = 30
    refresh_days: int = 7
    eager: bool = False  # run jobs inline (tests / no-Redis dev only; breaks worker isolation)
    scan_timeout: int = 900
    cors_origins: str = "http://localhost:5173"
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None


settings = Settings()
