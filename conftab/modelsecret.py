import json
import traceback

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text, VARCHAR, BigInteger, DateTime, JSON
from uuid import uuid1
import sqlalchemy.exc
import datetime
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from conftab.default import SQLALCHEMY_DATABASE_URL_SECRET
from fastapi import Request


print(f"db路径: {SQLALCHEMY_DATABASE_URL_SECRET}")
# 生成一个SQLAlchemy引擎
engine = create_engine(
    SQLALCHEMY_DATABASE_URL_SECRET,
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


def drop_db():   # 删除表
    Base.metadata.drop_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Mixin:
    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}

    @classmethod
    def get_columns(cls):
        return [str(col).split('.')[-1] for col in cls.__table__.columns]


class Key(Base, Mixin):
    __tablename__ = "key"
    uuid = Column(String(512), primary_key=True, index=True)

    project = Column(String(64), nullable=False, index=True)
    env = Column(String(64), nullable=False, index=True)
    ver = Column(String(64), nullable=False, index=True)

    conf_group_uuid = Column(String(512), index=True)
    key_pub = Column(String(4096))
    key_pri = Column(String(4096))
    conf_group_value = Column(Text())
    conf_group_value_type = Column(String(64), index=True)
    conf_group_value_secret = Column(Text())

    timecreate = Column(Integer, index=True)
    timeupdate = Column(Integer, index=True)
    time_create = Column(DateTime, index=True)
    time_update = Column(DateTime, index=True)


class ConfGroup(Base, Mixin):
    __tablename__ = "conf_group"
    uuid = Column(String(512), primary_key=True, index=True)

    project = Column(String(64), nullable=False, index=True)
    env = Column(String(64), nullable=False, index=True)
    ver = Column(String(64), nullable=False, index=True)

    value = Column(Text())  # conf_item_list
    value_type = Column(String(64), index=True)

    timecreate = Column(Integer, index=True)
    timeupdate = Column(Integer, index=True)
    time_create = Column(DateTime, index=True)
    time_update = Column(DateTime, index=True)


class ConfItem(Base, Mixin):
    __tablename__ = "conf_item"
    uuid = Column(String(512), primary_key=True, index=True)

    project = Column(String(64), nullable=True, index=True)
    env = Column(String(64), nullable=True, index=True)
    ver = Column(String(64), nullable=True, index=True)

    key = Column(String(64), index=True)
    value = Column(String(1024))
    value_type = Column(String(64), index=True)

    timecreate = Column(Integer, index=True)
    timeupdate = Column(Integer, index=True)
    time_create = Column(DateTime, index=True)
    time_update = Column(DateTime, index=True)


class Project(Base, Mixin):
    __tablename__ = "project"

    project_name = Column(String(32), primary_key=True, nullable=False, index=True, unique=True)
    project_type = Column(String(32), nullable=False, index=True)
    owner = Column(String(64))

    timecreate = Column(Integer, index=True)
    timeupdate = Column(Integer, index=True)
    time_create = Column(DateTime, index=True)
    time_update = Column(DateTime, index=True)


class Environment(Base, Mixin):
    __tablename__ = "environment"

    environment_name = Column(String(32), primary_key=True, nullable=False, index=True, unique=True)
    environment_type = Column(String(64), index=True)
    project_name = Column(String(32), nullable=False, index=True)
    project_type = Column(String(32), nullable=False, index=True)
    owner = Column(String(64))

    timecreate = Column(Integer, index=True)
    timeupdate = Column(Integer, index=True)
    time_create = Column(DateTime, index=True)
    time_update = Column(DateTime, index=True)


class Server(Base, Mixin):
    __tablename__ = "server"

    server_name = Column(String(32), primary_key=True, nullable=False, index=True, unique=True)
    server_type = Column(String(32), nullable=False, index=True)  # mysql/redis/es/mongo/filesystem/1
    host = Column(String(64))
    port = Column(Integer)
    username = Column(String(64))
    password = Column(String(256))

    timecreate = Column(Integer, index=True)
    timeupdate = Column(Integer, index=True)
    time_create = Column(DateTime, index=True)
    time_update = Column(DateTime, index=True)


class ServerDevice(Base, Mixin):
    __tablename__ = "server_device"

    uuid = Column(String(64), primary_key=True, nullable=False, index=True, unique=True)
    server_name = Column(String(32), nullable=False, index=True)
    server_type = Column(String(32), nullable=False, index=True)
    device_name = Column(String(32), nullable=False, index=True)
    device_type = Column(String(32), nullable=False, index=True)

    timecreate = Column(Integer, index=True)
    timeupdate = Column(Integer, index=True)
    time_create = Column(DateTime, index=True)
    time_update = Column(DateTime, index=True)


class Device(Base, Mixin):
    __tablename__ = "device"

    device_name = Column(String(32), primary_key=True, nullable=False, index=True, unique=True)
    device_type = Column(String(32), nullable=False, index=True)
    host_name = Column(String(64))
    ssh_ip = Column(String(64))
    ssh_port = Column(Integer)
    ssh_username = Column(String(64))
    ssh_password = Column(String(256))

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

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

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
