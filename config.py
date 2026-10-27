from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    API_KEY: str = "secure_shared_lab_key_2026"      # override with env var API_KEY
    DATABASE_URL: str = "sqlite+aiosqlite:///./platform.db"
    RUNNER_API_BASE: str = "http://127.0.0.1:8001"
    MOCK_RUNNER: bool = True                          # True = simulated lab runner
    TARGET_IP: str = "192.168.56.10"                  # lab target passed to /run/attack (matches the Vagrantfile's target IP)
    VERIFY_TIMEOUT_S: int = 120
    OPENAI_API_KEY: str = ""                          # empty = always use the fallback template
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_MODEL: str = "gpt-4o-mini"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
