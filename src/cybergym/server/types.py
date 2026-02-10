from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from cybergym.task.types import DEFAULT_SALT


class ServerConfig(BaseSettings):
    salt: str = Field(default=DEFAULT_SALT, description="Salt for checksum")
    log_dir: Path = Field(default=Path("./logs"), description="Directory to store logs")
    db_path: Path = Field(default=Path("./poc.db"), description="Path to SQLite DB")
    binary_dir: Path | None = Field(default=None, description="Directory to store target binaries")
    api_key: str = Field(
        default="cybergym-030a0cd7-5908-4862-8ab9-91f2bfc7b56d", description="API key for authentication"
    )
    api_key_name: str = Field(default="X-API-Key", description="Name of the API key header")
    max_file_size_mb: int = Field(default=10, description="Maximum file size for uploads in MB")

    model_config = SettingsConfigDict(env_prefix="CYBERGYM_")


server_conf = ServerConfig()


class Payload(BaseModel):
    task_id: str  # task_type:id, e.g., "arvo:1234"
    agent_id: str  # unique agent ID
    checksum: str  # checksum for verifying the task_id and agent_id
    data: bytes | None = None  # bytes
    require_flag: bool = False  # whether to require a flag or not


class PocQuery(BaseModel):
    agent_id: str | None = None
    task_id: str | None = None


class VerifyPocs(BaseModel):
    agent_id: str
