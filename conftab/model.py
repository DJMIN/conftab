import json
import traceback

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text, VARCHAR, BigInteger, DateTime
from uuid import uuid1
import datetime
import sqlalchemy.exc
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from conftab.default import SQLALCHEMY_DATABASE_URL
from fastapi import Request


print(f"db路径: {SQLALCHEMY_DATABASE_URL}")
# 生成一个SQLAlchemy引擎
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    # echo=True,
    connect_args={"check_same_thread": False},
)
# engine = create_engine(
#     SQLALCHEMY_DATABASE_URL,
#     pool_size=100,
#     pool_timeout=5,
#     pool_recycle=30,
#     max_overflow=0,
#     pool_pre_ping=True
# )
SessionLocal = sessionmaker(autocommit=False, autoflush=True, bind=engine)
Base = declarative_base()


def init_db():  # 初始化表
    Base.metadata.create_all(engine)


def drop_db():  # 删除表
    Base.metadata.drop_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Mixin:
    def __init__(self, **kwargs):
        cols = self.get_columns()
        for k, v in kwargs.items():
            if k in cols:
                setattr(self, k, v)

    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in self.get_columns()}

    @classmethod
    def get_columns(cls):
        return [c.name for c in getattr(cls, "__table__").columns]


class Conf(Base, Mixin):
    __tablename__ = "conf"
    uuid = Column(String(512), primary_key=True, index=True)
    project = Column(String(64), index=True)
    env = Column(String(64), index=True)
    ver = Column(String(64), index=True)
    key = Column(String(64), index=True)
    value = Column(Text())
    value_type = Column(String(64), index=True)
    timecreate = Column(Integer, index=True)
    timeupdate = Column(Integer, index=True)
    time_create = Column(DateTime, index=True)
    time_update = Column(DateTime, index=True)


class Audit(Base, Mixin):
    __tablename__ = "audit"

    uuid = Column(String(32), primary_key=True, nullable=False, index=True, unique=True)
    user = Column(String(256), index=True)
    client = Column(String(256), nullable=False, index=True)
    base_url = Column(String(1024), index=True)
    method = Column(String(16), nullable=False, index=True)
    headers = Column(Text())
    cookies = Column(Text())
    path_params = Column(Text())
    query_params = Column(Text())
    body = Column(Text())

    error = Column(Text())

    timecreate = Column(Integer, index=True)
    timeupdate = Column(Integer, index=True)
    time_create = Column(DateTime, index=True)
    time_update = Column(DateTime, index=True)


    @classmethod
    async def add_self(cls, db: Session, req: Request, error=None):
        time_now = datetime.datetime.now()
        data = dict(
            uuid=uuid1().__str__().replace('-', ''),
            timecreate=time_now.timestamp(),
            timeupdate=time_now.timestamp(),
            time_create=time_now,
            time_update=time_now,
            client=str(req.client),
            base_url=str(req.base_url),
            method=str(req.method),
            headers=json.dumps(dict(req.headers) or {}) or None,
            cookies=json.dumps(dict(req.cookies) or {}) or None,
            path_params=json.dumps(dict(req.path_params) or {}) or None,
            query_params=json.dumps(dict(req.query_params) or {}) or None,
            body=await req.body(),
            error=error if isinstance(error, str) or not error
            else f'[{error.__class__}] {error}\n{traceback.format_exc()}',
            user=None,
        )
        s = cls(**data)
        db.add(s)
        try:
            db.commit()
        except sqlalchemy.exc.PendingRollbackError:
            pass
        return s


if __name__ == '__main__':
    print(next(get_db()).query(Audit).filter(*(getattr(Audit, k) == v for k, v in {}.items())).one())
