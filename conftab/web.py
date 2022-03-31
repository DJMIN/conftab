import builtins
import datetime
import time
import traceback

import fastapi
import logging
from conftab.model import get_db, Conf, Session
from conftab.modelsecret import get_db as get_db_secret
from conftab.modelsecret import Session as Session_secret
from conftab import modelsecret
from conftab import model
from conftab.utils import get_req_data, format_to_table, format_to_form
from conftab.default import SQLALCHEMY_DATABASE_URL
from sqlalchemy import desc

logger = logging.getLogger('conftab.web')

item_clss_secret = {cls.__tablename__: cls for cls in (
    modelsecret.Key,
    modelsecret.ConfGroup,
    modelsecret.ConfItem,
    modelsecret.Project,
    modelsecret.Environment,
    modelsecret.Server,
    modelsecret.ServerDevice,
    modelsecret.Device,
    modelsecret.Audit,
)}

app = fastapi.FastAPI()


class AuditWithExceptionContextManager:
    """
    用上下文管理器捕获异常，可对代码片段进行错误捕捉，比装饰器更细腻
    """

    def __init__(self, db, req, verbose=0, raise__exception=False, a_cls=model.Audit):
        """
           :param verbose: 打印错误的深度,对应traceback对象的limit，为正整数
        """
        self.db = db
        self.req = req
        self.res = 'ok'
        self.req_data = {}
        self._verbose = verbose
        self._raise__exception = raise__exception
        self.a_cls = a_cls

    async def __aenter__(self):
        self.req_data = await get_req_data(self.req)
        return self

    @staticmethod
    def format_res(message, detail='', suc=True):
        return {
            'code': 20000 if suc else 50000,
            'status': '成功' if suc else "失败",
            'message': message,
            'detail': detail,
        }

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_tb is not None:
            ex_str = f'[{str(exc_type)}] {str(exc_val)}'
            tb = '\n'.join(
                traceback.format_tb(exc_tb)[:self._verbose]
                if self._verbose else traceback.format_tb(exc_tb))
            exc_tb_str = f'{ex_str}\n{tb}'
            self.res = self.format_res(message=ex_str, detail=exc_tb_str, suc=False)
            if not self._raise__exception:
                logger.error(exc_tb_str)
        else:
            exc_tb_str = None
        await self.a_cls.add_self(self.db, self.req, exc_tb_str)

        return not self._raise__exception  # __exit__方法 return True 不重新抛出错误


@app.get('/')
async def index():
    return {
        "server": 'conftab', "msg": "hello! http://127.0.0.1:7788/html/conf  http://127.0.0.1:7788/html/secret",
        "db": SQLALCHEMY_DATABASE_URL,
        'server_time': time.time()}


@app.get('/senderr')
async def senderr(req: fastapi.Request, db: Session = fastapi.Depends(get_db)):
    async with AuditWithExceptionContextManager(db, req) as ctx:
        raise ValueError(str(await get_req_data(req)))
    return ctx.res


@app.get('/api/conf/get')
async def get_conf(req: fastapi.Request, db: Session = fastapi.Depends(get_db)):
    logging.info(f'{dict(req.items())}')
    data = await get_req_data(req)
    res = db.query(Conf).filter(*(getattr(
        Conf, k) == v for k, v in data.items())).order_by(desc(Conf.timecreate)).limit(1).all()
    if len(res) == 1:
        res = res[0]
        return {'data': getattr(builtins, res.value_type)(res.value), "raw": res}
    elif len(res) > 1:
        res_raw = res
        return {'data': None, 'err': '配置超过两个，请检查', "raw": res_raw}
    else:
        return {'data': None, 'raw': {}}


@app.get('/api/conf/list')
async def list_conf(req: fastapi.Request, db: Session = fastapi.Depends(get_db)):
    data = await get_req_data(req)
    res = db.query(Conf).filter(*(getattr(Conf, k) == v for k, v in data.items())).all()
    return res


@app.post('/api/conf/set')
async def set_conf(req: fastapi.Request, db: Session = fastapi.Depends(get_db)):
    logging.info(f'{dict(req.items())}')
    async with AuditWithExceptionContextManager(db, req, a_cls=model.Audit) as ctx:
        data = await get_req_data(req)
        c = Conf(**data)
        c.uuid = f'{c.project}--{c.env}--{c.ver}--{c.key}--{c.value}'
        time_now = datetime.datetime.now()
        c.timecreate = time_now.timestamp()
        c.time_create = time_now
        db.merge(c)
        db.commit()
    return ctx.res


@app.get('/api/secretItem/{item_name}/one')
async def get_conf(item_name, req: fastapi.Request, db: Session_secret = fastapi.Depends(get_db_secret)):
    async with AuditWithExceptionContextManager(db, req, a_cls=modelsecret.Audit) as ctx:
        data = await get_req_data(req)
        cls = item_clss_secret.get(item_name)
        res = db.query(cls).filter(*(getattr(cls, k) == v for k, v in data.items())).order_by(
            desc(Conf.timecreate)).limit(1).all()
        if len(res) == 1:
            res = res[0]
            ctx.res = {'data': getattr(builtins, res.value_type)(res.value), "raw": res}
        elif len(res) > 1:
            res_raw = res
            ctx.res = {'data': None, 'err': '配置超过两个，请检查', "raw": res_raw}
        else:
            ctx.res = {'data': None, 'raw': {}}
    return ctx.res


@app.get('/api/secretItem/{item_name}/list')
async def list_conf(item_name, req: fastapi.Request, db: Session_secret = fastapi.Depends(get_db_secret)):
    async with AuditWithExceptionContextManager(db, req, a_cls=modelsecret.Audit) as ctx:
        data = await get_req_data(req)
        cls = item_clss_secret.get(item_name)
        ctx.res = db.query(cls).filter(*(getattr(cls, k) == v for k, v in data.items())).all()
    return ctx.res


@app.post('/api/secretItem/{item_name}')
async def set_conf(item_name, req: fastapi.Request, db: Session_secret = fastapi.Depends(get_db_secret)):
    async with AuditWithExceptionContextManager(db, req, a_cls=modelsecret.Audit) as ctx:
        data = await get_req_data(req)
        c = item_clss_secret.get(item_name)(**data)
        # c.uuid = f'{c.project}--{c.env}--{c.ver}--{c.key}--{c.value}'
        time_now = datetime.datetime.now()
        c.timecreate = time_now.timestamp()
        c.time_create = time_now
        c.timeupdate = time_now.timestamp()
        c.time_update = time_now
        db.merge(c)
        db.commit()
    return ctx.res


@app.get('/html/conf', response_class=fastapi.responses.HTMLResponse)
async def html_list_conf(req: fastapi.Request, db: Session = fastapi.Depends(get_db)):
    data = await get_req_data(req)
    res = list(d.to_dict() for d in db.query(Conf).filter(*(getattr(Conf, k) == v for k, v in data.items())).all())
    return format_to_table(
        res,
        keys=['project', 'env', 'ver', 'time_create', 'time_update', 'value_type', 'key', 'value'])


@app.get('/html/secret/{item_name:path}', response_class=fastapi.responses.HTMLResponse)
async def html_list_secret(
        item_name,
        req: fastapi.Request,
        db: Session = fastapi.Depends(get_db_secret)):
    data = await get_req_data(req)
    cls = item_clss_secret.get(item_name)
    if not cls:
        return "无此表格，请在{}中选择".format(
            ', '.join(f'<a href="/html/secret/{key}">{key}</a>' for key in item_clss_secret.keys())
        )
    res = list(d.to_dict()
               for d in db.query(cls).filter(*(getattr(cls, k) == v for k, v in data.items())).all()
               )
    return format_to_form(f"/api/secretItem/{item_name}", cls.get_columns()) + format_to_table(
        res, keys=cls.get_columns())
