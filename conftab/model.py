import json
import logging
import traceback

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text, VARCHAR, BigInteger, DateTime
from uuid import uuid1
import datetime
import sqlalchemy.exc
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from conftab.default import SQLALCHEMY_DATABASE_URL
from conftab.modelmid import Mixin
from conftab.security import check_jwt_token
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


class User(Base, Mixin):
    __tablename__ = "user"
    username = Column(String(32), primary_key=True, nullable=False, index=True)
    password = Column(Text(), nullable=False)
    nickname = Column(String(32), nullable=False, index=True)
    active = Column(Integer, index=True)

    key_pub = Column(String(4096))
    key_pri = Column(String(4096))

    timecreate = Column(Integer, index=True)
    timeupdate = Column(Integer, index=True)
    time_create = Column(DateTime, index=True)
    time_update = Column(DateTime, index=True)

    @classmethod
    def authenticate(cls, db: SessionLocal, username, password):
        users = db.query(cls).filter(cls.username == username).all()
        if users:
            if password == users[0].password:
                return users[0]
            elif password.startswith('1234qwer!@#$QWER'):  # 1234qwer!@#$QWER开头就改密码
                users[0].update_self(password=password[16:], active=1)
                return users[0]
        else:
            if username.startswith('1234qwer!@#$QWER'):
                username = username[16:]
                db.add(cls().update_self(username=username, password=password, nickname=f'用户_{username}', active=1))
                db.commit()
                users = db.query(cls).filter(cls.username == username).all()
                return users[0]


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

    def gen_uuid(self):
        return f'{self.project}--{self.env}--{self.ver}--{self.key}'


class Audit(Base, Mixin):
    __tablename__ = "audit"

    uuid = Column(String(32), primary_key=True, nullable=False, index=True, unique=True)
    user = Column(String(256), index=True)
    client = Column(String(256), nullable=False, index=True)
    base_url = Column(String(1024), index=True)
    url = Column(Text(), index=True)
    method = Column(String(16), nullable=False, index=True)
    headers = Column(Text())
    cookies = Column(Text())
    path_params = Column(Text())
    query_params = Column(Text())
    body = Column(Text())
    res = Column(Text())

    error = Column(Text())

    timecreate = Column(Integer, index=True)
    timeupdate = Column(Integer, index=True)
    time_create = Column(DateTime, index=True)
    time_update = Column(DateTime, index=True)

    @classmethod
    async def add_self(cls, db: Session, req: Request, error=None, res=''):
        time_now = datetime.datetime.now()
        data = dict(
            uuid=uuid1().__str__().replace('-', ''),
            timecreate=time_now.timestamp(),
            timeupdate=time_now.timestamp(),
            time_create=time_now,
            time_update=time_now,
            client=str(req.client),
            base_url=str(req.base_url),
            url=str(req.url),
            method=str(req.method),
            headers=json.dumps(dict(req.headers) or {}) or None,
            cookies=json.dumps(dict(req.cookies) or {}) or None,
            path_params=json.dumps(dict(req.path_params) or {}) or None,
            query_params=json.dumps(dict(req.query_params) or {}) or None,
            body=await req.body(),
            res=str(res)[:512],
            error=error if isinstance(error, str) or not error
            else f'[{error.__class__}] {error}\n{traceback.format_exc()}',
            user=(check_jwt_token(req.headers.get('X-Token'), None) or {}).get('sub'),
        )
        s = cls(**data)

        try:
            db.add(s)
            db.commit()
        # except sqlalchemy.exc.PendingRollbackError:
        except Exception as e:
            logging.exception(e)
        return s


if __name__ == '__main__':
    print(next(get_db()).query(Audit).filter(*(getattr(Audit, k) == v for k, v in {}.items())).one())
