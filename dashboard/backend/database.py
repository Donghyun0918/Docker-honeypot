from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, create_engine
from datetime import datetime

import os as _os
_DB_DIR = _os.getenv("DB_DIR", ".")
_os.makedirs(_DB_DIR, exist_ok=True)

DATABASE_URL      = f"sqlite+aiosqlite:///{_DB_DIR}/dashboard.db"
DATABASE_URL_SYNC = f"sqlite:///{_DB_DIR}/dashboard.db"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# 스레드에서 히스토리 쓰기용 동기 엔진
sync_engine = create_engine(DATABASE_URL_SYNC, connect_args={"check_same_thread": False})
SyncSessionLocal = sessionmaker(sync_engine)

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    deactivated_at = Column(DateTime, nullable=True)


class ScenarioRun(Base):
    __tablename__ = "scenario_runs"

    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String, index=True, nullable=False)
    scenario_id   = Column(String, nullable=False)
    scenario_name = Column(String, nullable=False)
    label         = Column(String, nullable=False)
    state         = Column(String, nullable=False)   # done / failed
    started_at    = Column(DateTime, nullable=True)
    finished_at   = Column(DateTime, nullable=True)
    output        = Column(Text, default="")


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
