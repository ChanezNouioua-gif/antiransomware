"""Configuration centrale, lue depuis les variables d'environnement / le fichier .env.

Usage :
    from app.config import get_settings
    settings = get_settings()
"""

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application ---
    app_env: str = "dev"  # dev | test | prod
    log_level: str = "INFO"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:3000"]

    # --- Sécurité des actions ---
    # Tant que dry_run est vrai, AUCUNE action de réponse réelle n'est exécutée
    # (suspension, kill, quarantaine...) : elles sont seulement journalisées.
    dry_run: bool = True

    # --- Monitor : surveillance ---
    watched_paths: Annotated[list[Path], NoDecode] = [Path("./sandbox/watched")]
    canary_dir: Path = Path("./sandbox/watched/.canary")
    ignored_patterns: Annotated[list[str], NoDecode] = ["*.tmp", "*.swp", "*.log", "*.pyc"]

    # --- Monitor : seuils de détection ---
    window_seconds: float = Field(default=5.0, gt=0)        # fenêtre glissante d'agrégation
    dedup_cooldown_seconds: float = Field(default=60.0, ge=0)  # pas de nouvelle alerte pour le même PID
    min_files_modified: int = Field(default=20, ge=1)       # fichiers modifiés par fenêtre
    entropy_threshold: float = Field(default=7.5, ge=0, le=8)  # bits/octet : au-dessus = chiffré/compressé
    entropy_sample_bytes: int = Field(default=65536, ge=1024)  # octets lus pour calculer l'entropie
    min_rename_count: int = Field(default=10, ge=1)
    write_rate_threshold: float = Field(default=30.0, gt=0)    # modifications / seconde

    # --- Intégrité ---
    baseline_db_path: Path = Path("./data/baseline.db")
    baseline_hmac_key: SecretStr = SecretStr("change-me")  # protège la baseline contre la falsification

    # --- ClamAV (daemon clamd) ---
    clamav_enabled: bool = True
    clamav_socket: str | None = "/var/run/clamav/clamd.ctl"
    clamav_host: str | None = None
    clamav_port: int = 3310

    # --- LLM / agents ---
    llm_model: str = "claude-sonnet-5-5"
    anthropic_api_key: SecretStr | None = None
    llm_timeout_seconds: float = Field(default=60.0, gt=0)
    llm_max_retries: int = Field(default=2, ge=0)
    agent_max_steps: int = Field(default=8, ge=1)  # garde-fou : tours d'outils max par agent

    # --- Persistance ---
    database_url: str = "sqlite+aiosqlite:///./data/antiransom.db"
    checkpoint_db_path: Path = Path("./data/checkpoints.db")  # checkpointer LangGraph

    # Listes passées en variable d'env sous forme "a,b,c"
    @field_validator("cors_origins", "ignored_patterns", mode="before")
    @classmethod
    def _split_csv(cls, v):
        if isinstance(v, str):
            return [p.strip() for p in v.split(",") if p.strip()]
        return v

    @field_validator("watched_paths", mode="before")
    @classmethod
    def _split_paths(cls, v):
        if isinstance(v, str):
            return [Path(p.strip()) for p in v.split(",") if p.strip()]
        return v

    @field_validator("anthropic_api_key", "clamav_socket", "clamav_host", mode="before")
    @classmethod
    def _empty_to_none(cls, v):
        # Une variable vide dans le .env (ANTHROPIC_API_KEY=) doit valoir "non définie"
        return None if isinstance(v, str) and not v.strip() else v

    @property
    def is_prod(self) -> bool:
        return self.app_env == "prod"


@lru_cache
def get_settings() -> Settings:
    return Settings()
