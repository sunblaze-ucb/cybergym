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
from cybergym.server.types import Payload, PocQuery, VerifyPocs
from cybergym.task.types import DEFAULT_SALT

SALT = DEFAULT_SALT
LOG_DIR = Path("./logs")
DB_PATH = Path("./poc.db")
OSS_FUZZ_PATH = Path("./oss-fuzz-data")
API_KEY = "cybergym-030a0cd7-5908-4862-8ab9-91f2bfc7b56d"
API_KEY_NAME = "X-API-Key"

engine: Engine = None


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    engine = init_engine(DB_PATH)

    yield

    if engine:
        engine.dispose()


app = FastAPI(lifespan=lifespan)

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


def get_api_key(api_key: str = Security(api_key_header)):
    if api_key == API_KEY:
        return api_key
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


public_router = APIRouter()
private_router = APIRouter(dependencies=[Depends(get_api_key)])


@public_router.post("/submit-vul")
def submit_vul(db: SessionDep, metadata: Annotated[str, Form()], file: Annotated[UploadFile, File()]):
    try:
        payload = Payload.model_validate_json(metadata)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid metadata format") from None
    payload.data = file.file.read()
    res = submit_poc(db, payload, mode="vul", log_dir=LOG_DIR, salt=SALT, oss_fuzz_path=OSS_FUZZ_PATH)
    res = _post_process_result(res)
    return res


@private_router.post("/submit-fix")
def submit_fix(db: SessionDep, metadata: Annotated[str, Form()], file: Annotated[UploadFile, File()]):
    try:
        payload = Payload.model_validate_json(metadata)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid metadata format") from None
    payload.data = file.file.read()
    res = submit_poc(db, payload, mode="fix", log_dir=LOG_DIR, salt=SALT, oss_fuzz_path=OSS_FUZZ_PATH)
    res = _post_process_result(res)
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
        run_poc_id(db, LOG_DIR, record.poc_id, oss_fuzz_path=OSS_FUZZ_PATH)

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
    parser.add_argument("--salt", type=str, default=SALT, help="Salt for checksum")
    parser.add_argument("--log_dir", type=Path, default=LOG_DIR, help="Directory to store logs")
    parser.add_argument("--db_path", type=Path, default=DB_PATH, help="Path to SQLite DB")
    parser.add_argument("--cybergym_oss_fuzz_path", type=Path, default=OSS_FUZZ_PATH, help="Path to OSS-Fuzz")

    args = parser.parse_args()
    SALT = args.salt
    LOG_DIR = args.log_dir
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    DB_PATH = Path(args.db_path)

    OSS_FUZZ_PATH = Path(args.cybergym_oss_fuzz_path)

    uvicorn.run(app, host=args.host, port=args.port)
