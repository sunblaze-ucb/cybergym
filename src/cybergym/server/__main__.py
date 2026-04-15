import argparse
import logging
from contextlib import asynccontextmanager
from pathlib import Path
import time
from typing import Annotated

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Request, Security, UploadFile, status
from fastapi.security import APIKeyHeader
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from cybergym.server.pocdb import get_poc_by_hash, init_engine
from cybergym.server.rate_limiter import RateLimiter
from cybergym.server.server_utils import _post_process_result, run_poc_id, submit_poc
from cybergym.server.types import Payload, PocQuery, VerifyPocs, server_conf
from cybergym.task.mask import load_mask_map
from cybergym.task.types import verify_task

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def make_log_config(log_file: str) -> dict:
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": LOG_FORMAT,
                "datefmt": LOG_DATE_FORMAT,
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "stream": "ext://sys.stderr",
            },
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "formatter": "default",
                "filename": log_file,
                "maxBytes": 10 * 1024 * 1024,  # 10 MB
                "backupCount": 5,
            },
        },
        "loggers": {
            "uvicorn": {"handlers": ["console", "file"], "level": "INFO", "propagate": False},
            "uvicorn.error": {"handlers": ["console", "file"], "level": "INFO", "propagate": False},
            "uvicorn.access": {"handlers": ["console", "file"], "level": "INFO", "propagate": False},
            "cybergym.server": {"handlers": ["console", "file"], "level": "INFO", "propagate": False},
        },
    }


logger = logging.getLogger("cybergym.server")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)

engine: Engine = None
rate_limiter: RateLimiter = None


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine, rate_limiter
    logger.info("Starting server: db_path=%s, log_dir=%s", server_conf.db_path, server_conf.log_dir)
    engine = init_engine(server_conf.db_path)
    rate_limiter = RateLimiter(
        max_requests=server_conf.rate_limit_max_requests, window_seconds=server_conf.rate_limit_window_seconds
    )
    logger.info("Server ready")

    yield

    logger.info("Shutting down server")
    if engine:
        engine.dispose()


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info(
        "%s %s -> %d (%.1fms)",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


api_key_header = APIKeyHeader(name=server_conf.api_key_name, auto_error=False)


def get_api_key(api_key: str = Security(api_key_header)):
    if api_key == server_conf.api_key:
        return api_key
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


def try_read_file(file: UploadFile, max_size_mb: int) -> bytes:
    """Helper function to check file size."""
    max_size_bytes = max_size_mb * 1024 * 1024
    content = file.file.read(max_size_bytes + 1)
    if len(content) > max_size_bytes:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum size allowed: {max_size_mb}MB")
    return content


public_router = APIRouter()
private_router = APIRouter(dependencies=[Depends(get_api_key)])


@public_router.post("/submit-vul")
def submit_vul(db: SessionDep, metadata: Annotated[str, Form()], file: Annotated[UploadFile, File()]):
    # Read and validate file size
    try:
        file_content = try_read_file(file, server_conf.max_file_size_mb)
    except HTTPException:
        raise
    except Exception:
        logger.warning("Failed to read uploaded file")
        raise HTTPException(status_code=400, detail="Error reading file") from None

    try:
        payload = Payload.model_validate_json(metadata)
    except Exception:
        logger.warning("Invalid metadata in submit-vul request")
        raise HTTPException(status_code=400, detail="Invalid metadata format") from None

    logger.info("submit-vul: agent=%s task=%s file_size=%d", payload.agent_id, payload.task_id, len(file_content))

    if not verify_task(payload.task_id, payload.agent_id, payload.checksum, salt=server_conf.salt):
        raise HTTPException(status_code=400, detail="Invalid checksum")

    rate_limiter.check(payload.agent_id)

    payload.data = file_content
    binary_only_mode = bool(server_conf.binary_dir)
    res = submit_poc(
        db, payload, mode="vul", log_dir=server_conf.log_dir, salt=server_conf.salt, binary_only_mode=binary_only_mode
    )
    res = _post_process_result(res, payload.require_flag)
    logger.info("submit-vul done: agent=%s task=%s exit_code=%s", payload.agent_id, payload.task_id, res["exit_code"])
    return res


@private_router.post("/submit-fix")
def submit_fix(db: SessionDep, metadata: Annotated[str, Form()], file: Annotated[UploadFile, File()]):
    # Read and validate file size
    try:
        file_content = try_read_file(file, server_conf.max_file_size_mb)
    except HTTPException:
        raise
    except Exception:
        logger.warning("Failed to read uploaded file")
        raise HTTPException(status_code=400, detail="Error reading file") from None

    try:
        payload = Payload.model_validate_json(metadata)
    except Exception:
        logger.warning("Invalid metadata in submit-fix request")
        raise HTTPException(status_code=400, detail="Invalid metadata format") from None

    logger.info("submit-fix: agent=%s task=%s file_size=%d", payload.agent_id, payload.task_id, len(file_content))

    payload.data = file_content
    binary_only_mode = bool(server_conf.binary_dir)
    res = submit_poc(
        db, payload, mode="fix", log_dir=server_conf.log_dir, salt=server_conf.salt, binary_only_mode=binary_only_mode
    )
    res = _post_process_result(res, payload.require_flag)
    logger.info("submit-fix done: agent=%s task=%s exit_code=%s", payload.agent_id, payload.task_id, res["exit_code"])
    return res


@private_router.post("/query-poc")
def query_db(db: SessionDep, query: PocQuery):
    logger.info("query-poc: agent=%s task=%s", query.agent_id, query.task_id)
    records = get_poc_by_hash(db, query.agent_id, query.task_id)
    if not records:
        raise HTTPException(status_code=404, detail="Record not found")
    return [record.to_dict() for record in records]


@private_router.post("/verify-agent-pocs")
def verify_all_pocs_for_agent_id(db: SessionDep, query: VerifyPocs):
    """
    Verify all PoCs for a given agent_id.
    """
    logger.info("verify-agent-pocs: agent=%s", query.agent_id)
    records = get_poc_by_hash(db, query.agent_id)
    if not records:
        raise HTTPException(status_code=404, detail="No records found for this agent_id")

    for record in records:
        if record.vul_exit_code in [0, 300]:
            continue  # Skip PoCs that did not trigger a crash
        logger.info("Re-verifying poc_id=%s task=%s", record.poc_id, record.task_id)
        run_poc_id(db, server_conf.log_dir, record.poc_id, binary_only_mode=bool(server_conf.binary_dir))
        time.sleep(0.5)  # Small delay to avoid overwhelming the docker

    logger.info("verify-agent-pocs done: agent=%s count=%d", query.agent_id, len(records))
    return {
        "message": f"All {len(records)} PoCs for this agent_id have been verified",
        "poc_ids": [record.poc_id for record in records],
    }


app.include_router(public_router)
app.include_router(private_router)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberGym Server")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to run the server on")
    parser.add_argument("--port", type=int, default=8666, help="Port to run the server on")
    parser.add_argument("--salt", type=str, default=server_conf.salt, help="Salt for checksum")
    parser.add_argument(
        "--mask_map_path", type=Path, default=server_conf.mask_map_path, help="Path to task ID mask mapping JSON file"
    )
    parser.add_argument("--log_dir", type=Path, default=server_conf.log_dir, help="Directory to store logs")
    parser.add_argument("--db_path", type=Path, default=server_conf.db_path, help="Path to SQLite DB")
    parser.add_argument(
        "--binary_dir", type=Path, default=server_conf.binary_dir, help="Directory to store target binaries"
    )
    parser.add_argument(
        "--max_file_size_mb", type=int, default=server_conf.max_file_size_mb, help="Maximum file size for uploads in MB"
    )
    parser.add_argument(
        "--rate_limit_max_requests",
        type=int,
        default=server_conf.rate_limit_max_requests,
        help="Max requests per agent per window",
    )
    parser.add_argument(
        "--rate_limit_window_seconds",
        type=int,
        default=server_conf.rate_limit_window_seconds,
        help="Rate limit window in seconds",
    )

    args = parser.parse_args()

    server_conf.salt = args.salt
    server_conf.mask_map_path = args.mask_map_path
    server_conf.log_dir = args.log_dir
    server_conf.log_dir.mkdir(parents=True, exist_ok=True)
    server_conf.db_path = Path(args.db_path)
    server_conf.binary_dir = args.binary_dir
    server_conf.max_file_size_mb = args.max_file_size_mb
    server_conf.rate_limit_max_requests = args.rate_limit_max_requests
    server_conf.rate_limit_window_seconds = args.rate_limit_window_seconds

    if server_conf.mask_map_path:
        load_mask_map(server_conf.mask_map_path)

    uvicorn.run(
        app, host=args.host, port=args.port, log_config=make_log_config(str(server_conf.log_dir / "server.log"))
    )
