import datetime
from pathlib import Path

from sqlalchemy import Column, DateTime, Engine, Integer, String, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Session


class Base(DeclarativeBase):
    pass


def now():
    return datetime.datetime.now(datetime.UTC)


class PoCRecord(Base):
    __tablename__ = "poc_records"
    id = Column(Integer, primary_key=True)
    agent_id = Column(String, index=True)
    task_id = Column(String, index=True)
    poc_id = Column(String, unique=True, index=True)
    poc_hash = Column(String, index=True)
    poc_length = Column(Integer, nullable=True)
    vul_exit_code = Column(Integer, nullable=True)
    fix_exit_code = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=now, nullable=False)
    updated_at = Column(DateTime, default=now, onupdate=now, nullable=False)
    __table_args__ = (UniqueConstraint("agent_id", "task_id", "poc_hash", name="_agent_task_hash_uc"),)

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "poc_id": self.poc_id,
            "poc_hash": self.poc_hash,
            "poc_length": self.poc_length,
            "vul_exit_code": self.vul_exit_code,
            "fix_exit_code": self.fix_exit_code,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def get_or_create_poc(
    db: Session, agent_id: str, task_id: str, poc_id: str, poc_hash: str, poc_length: int
) -> PoCRecord:
    record = db.query(PoCRecord).filter_by(agent_id=agent_id, task_id=task_id, poc_hash=poc_hash).first()
    if record:
        return record
    record = PoCRecord(
        agent_id=agent_id,
        task_id=task_id,
        poc_id=poc_id,
        poc_hash=poc_hash,
        poc_length=poc_length,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def update_poc_output(db: Session, record: PoCRecord, mode: str, exit_code: int):
    if mode == "vul":
        record.vul_exit_code = exit_code
    elif mode == "fix":
        record.fix_exit_code = exit_code
    db.commit()


def get_poc_by_hash(
    db: Session,
    agent_id: str | None = None,
    task_id: str | None = None,
    poc_hash: str | None = None,
) -> list[PoCRecord]:
    filters = {}
    if agent_id is not None:
        filters["agent_id"] = agent_id
    if task_id is not None:
        filters["task_id"] = task_id
    if poc_hash is not None:
        filters["poc_hash"] = poc_hash
    if not filters:
        return None  # or raise ValueError("At least one filter must be provided")

    # TODO: add limit
    return db.query(PoCRecord).filter_by(**filters).all()


def init_engine(db_path: Path) -> Engine:
    engine = create_engine(
        f"sqlite:///{db_path}", echo=False, connect_args={"check_same_thread": False}, pool_size=64, max_overflow=64
    )
    Base.metadata.create_all(engine)
    return engine
