from __future__ import annotations

import os
from dataclasses import dataclass

def _load_dotenv(path: str = ".env") -> None:
    """Small .env reader to keep the Jetstream client dependency-light."""
    try:
        with open(path, encoding="utf-8") as env_file:
            for line in env_file:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip("'\""))
    except FileNotFoundError:
        pass

_load_dotenv()


@dataclass(frozen=True)
class Settings:
    """Jetstream connection settings, following the structure in src/config.py."""
    base_url: str = os.getenv("JETSTREAM_BASE_URL", "https://llm.jetstream-cloud.org/gpt-oss-120b/v1")
    api_key: str = os.getenv("JETSTREAM_API_KEY", "not-required")
    model_name: str = os.getenv("JETSTREAM_MODEL_NAME", "gpt-oss-120b")
    temperature: float = float(os.getenv("MODEL_TEMPERATURE", "0"))
    timeout_seconds: int = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))


def get_settings() -> Settings:
    return Settings()
