from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text, VARCHAR, BigInteger, DateTime
from uuid import UUID
from datetime import datetime, time, timedelta
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from conftab.default import SQLALCHEMY_DATABASE_URL


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


class Conf(Base, Mixin):
    __tablename__ = "conf"
    uuid = Column(String(512), primary_key=True, index=True)
    project = Column(String(64), index=True)
    env = Column(String(64), index=True)
    ver = Column(String(64), index=True)
    key = Column(String(64), index=True)
    value = Column(String(1024))
    value_type = Column(String(64), index=True)
    timecreate = Column(Integer, index=True)
    timeupdate = Column(Integer, index=True)
    time_create = Column(DateTime, index=True)
    time_update = Column(DateTime, index=True)


class Server(Base, Mixin):
    __tablename__ = "server"

    server_name = Column(String(32), primary_key=True, nullable=False, index=True, unique=True)
    server_type = Column(String(32), nullable=False, index=True)
    host = Column(String(64))
    port = Column(Integer)
    username = Column(String(64))
    password = Column(String(256))
    db = Column(String(256))


