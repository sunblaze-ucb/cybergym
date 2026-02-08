import argparse
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Security, UploadFile, status
from fastapi.security import APIKeyHeader
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from cybergym.server.pocdb import get_poc_by_hash, init_engine
from cybergym.server.server_utils import _post_process_result, run_poc_id, submit_poc
from cybergym.server.types import Payload, PocQuery, VerifyPocs, server_conf

engine: Engine = None


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    engine = init_engine(server_conf.db_path)

    yield

    if engine:
        engine.dispose()


app = FastAPI(lifespan=lifespan)

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
        raise HTTPException(status_code=400, detail="Error reading file") from None

    try:
        payload = Payload.model_validate_json(metadata)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid metadata format") from None
    payload.data = file_content
    use2 = bool(server_conf.binary_dir)
    res = submit_poc(db, payload, mode="vul", log_dir=server_conf.log_dir, salt=server_conf.salt, use2=use2)
    res = _post_process_result(res, payload.require_flag)
    return res


@private_router.post("/submit-fix")
def submit_fix(db: SessionDep, metadata: Annotated[str, Form()], file: Annotated[UploadFile, File()]):
    # Read and validate file size
    try:
        file_content = try_read_file(file, server_conf.max_file_size_mb)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Error reading file") from None

    try:
        payload = Payload.model_validate_json(metadata)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid metadata format") from None
    payload.data = file_content
    use2 = bool(server_conf.binary_dir)
    res = submit_poc(db, payload, mode="fix", log_dir=server_conf.log_dir, salt=server_conf.salt, use2=use2)
    res = _post_process_result(res, payload.require_flag)
    return res


@private_router.post("/query-poc")
def query_db(db: SessionDep, query: PocQuery):
    records = get_poc_by_hash(db, query.agent_id, query.task_id)
    if not records:
        raise HTTPException(status_code=404, detail="Record not found")
    return [record.to_dict() for record in records]


@private_router.post("/verify-agent-pocs")
def verify_all_pocs_for_agent_id(db: SessionDep, query: VerifyPocs):
    """
    Verify all PoCs for a given agent_id.
    """
    records = get_poc_by_hash(db, query.agent_id)
    if not records:
        raise HTTPException(status_code=404, detail="No records found for this agent_id")

    for record in records:
        run_poc_id(db, server_conf.log_dir, record.poc_id)

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
    parser.add_argument("--log_dir", type=Path, default=server_conf.log_dir, help="Directory to store logs")
    parser.add_argument("--db_path", type=Path, default=server_conf.db_path, help="Path to SQLite DB")
    parser.add_argument(
        "--binary_dir", type=Path, default=server_conf.binary_dir, help="Directory to store target binaries"
    )
    parser.add_argument(
        "--max_file_size_mb", type=int, default=server_conf.max_file_size_mb, help="Maximum file size for uploads in MB"
    )

    args = parser.parse_args()

    server_conf.salt = args.salt
    server_conf.log_dir = args.log_dir
    server_conf.log_dir.mkdir(parents=True, exist_ok=True)
    server_conf.db_path = Path(args.db_path)
    server_conf.binary_dir = args.binary_dir

    uvicorn.run(app, host=args.host, port=args.port)
