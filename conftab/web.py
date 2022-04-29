import builtins
import datetime
import json
import os.path
import time
import traceback
import typing
import guesstime
import fastapi
import fastapi.responses
import logging

from sqlalchemy.dialects.sqlite import TEXT
from sqlalchemy.sql.expression import func
from conftab.model import get_db, Conf, Session
from conftab.modelsecret import get_db as get_db_secret
from conftab.modelsecret import Session as Session_secret
from conftab import modelsecret
from conftab import model
from conftab import default
from conftab.cyhper import RSACtrl
from conftab.utils import get_req_data, format_to_table, format_to_form
from conftab.default import SQLALCHEMY_DATABASE_URL, SQLALCHEMY_DATABASE_URL_SECRET, PUBKEY_PATH, PRIKEY_PATH
from conftab.security import create_access_token, check_jwt_token, ACCESS_TOKEN_EXPIRE_MINUTES
from sqlalchemy import desc

from typing import List, Optional, Union, Any
from pydantic import BaseModel, Field

logger = logging.getLogger('conftab.web')

item_clss_secret = {cls.__tablename__: cls for cls in (
    modelsecret.User,
    modelsecret.ConfGroup,
    modelsecret.ConfItem,
    modelsecret.Project,
    modelsecret.Environment,
    modelsecret.ServerConfItem,
    modelsecret.Server,
    modelsecret.ServerDevice,
    modelsecret.Device,
    modelsecret.Audit,
)}

item_clss_pub = {cls.__tablename__: cls for cls in (
    model.Conf,
    model.Audit,
)}


def to_datetime(string):
    return guesstime.GuessTime(string, raise_err=False).to_datetime()


def to_int(string):
    try:
        res = int(string)
    except ValueError:
        res = 0
    return res


change_type = {
    "INTE": to_int,
    "VARC": str,
    "TEXT": str,
    "DATE": to_datetime,
}

rsa_ctrl = RSACtrl(privatekey_path=PRIKEY_PATH, publickey_path=PUBKEY_PATH).load_or_generate_key(2048)
app = fastapi.FastAPI()


class AuditWithExceptionContextManager:
    """
    用上下文管理器捕获异常，可对代码片段进行错误捕捉，比装饰器更细腻
    """

    def __init__(self, db, req, verbose=None, raise__exception=False, a_cls=model.Audit):
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
    def format_res(message, detail: typing.Union[str, dict, None] = '', suc=True):
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
                traceback.format_tb(exc_tb, self._verbose)
                if self._verbose else traceback.format_tb(exc_tb))
            exc_tb_str = f'{ex_str}\n{tb}'
            self.res = self.format_res(message=ex_str, detail=exc_tb_str, suc=False)
            if not self._raise__exception:
                logger.error(exc_tb_str)
        else:
            exc_tb_str = None
        await self.a_cls.add_self(self.db, self.req, exc_tb_str, self.res)

        return not self._raise__exception  # __exit__方法 return True 不重新抛出错误


@app.get('/')
async def index():
    return {
        "server": 'conftab', "msg": "hello! http://127.0.0.1:7788/html/conf  http://127.0.0.1:7788/html/secret",
        "db": SQLALCHEMY_DATABASE_URL,
        "db_secert": SQLALCHEMY_DATABASE_URL_SECRET,
        "pubkey": rsa_ctrl.public_key,
        'server_time': time.time()}


@app.get('/api/pubkey', response_class=fastapi.responses.PlainTextResponse)
async def pubkey_show():
    return rsa_ctrl.public_key


@app.get('/api/keyRandom')
async def key_random():
    time_start = time.time()
    rsa_c = RSACtrl().load_or_generate_key(2048)

    return {
        "use_time": time.time() - time_start,
        "pub": rsa_c.public_key,
        "pri": rsa_c.private_key,
        'server_time': time.time()
    }


@app.get('/api/isCtrl')
async def is_ctrl(
        req: fastapi.Request,
        token_data: Union[str, Any] = fastapi.Depends(check_jwt_token)
):
    data = await get_req_data(req)
    db_path = SQLALCHEMY_DATABASE_URL_SECRET.split('sqlite:///')[-1]
    db_status = 1 if os.path.exists(db_path) and open(db_path, 'rb').read().startswith(b'SQLite format') else 0
    return {
        "status": 1 if data.get('status') else db_status,
        "db_path": SQLALCHEMY_DATABASE_URL_SECRET,
        "work_path": os.getcwd(),
        "user": token_data,
        'server_time': time.time()
    }


@app.get('/api/openDB')
async def is_ctrl(
        req: fastapi.Request,
        token_data: Union[str, Any] = fastapi.Depends(check_jwt_token)
):
    db_path = SQLALCHEMY_DATABASE_URL_SECRET.split('sqlite:///')[-1]
    db_path_backup = f'{db_path}.backup'

    if os.path.exists(db_path_backup):
        if os.path.exists(db_path):
            os.remove(db_path)
        os.rename(db_path_backup, db_path)
        res = '已打开数据库'
    else:
        if os.path.exists(db_path_backup):
            os.remove(db_path_backup)
        os.rename(db_path, db_path_backup)
        res = '已关闭数据库'

    return {
        "message": res,
        "db_path": SQLALCHEMY_DATABASE_URL_SECRET,
        "work_path": os.getcwd(),
        "user": token_data,
        'server_time': time.time()
    }


@app.get('/api/senderr')
async def senderr(req: fastapi.Request, db: Session = fastapi.Depends(get_db)):
    async with AuditWithExceptionContextManager(db, req) as ctx:
        raise ValueError(str(await get_req_data(req)))
    return ctx.res


class UserInfo(BaseModel):
    username: str
    password: str


@app.post("/api/login/access-token", summary="用户登录认证")
async def login_access_token(
        *,
        req: fastapi.Request,
        db: Session = fastapi.Depends(get_db),
        user_info: UserInfo,
) -> Any:
    """
    用户登录
    :param db:
    :param user_info:
    :return:
    """

    async with AuditWithExceptionContextManager(db, req, a_cls=model.Audit) as ctx:
        # 验证用户账号密码是否正确
        user = model.User.authenticate(db, username=user_info.username, password=user_info.password)

        if not user:
            logger.info(f"用户认证错误, username:{user_info.username} password:{user_info.password}")
            ctx.res = ctx.format_res("用户名或者密码错误", suc=False)
        elif not user.active:
            ctx.res = ctx.format_res("用户未激活", suc=False)

        # 如果用户正确通过 则生成token
        # 设置过期时间
        access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        # 登录token 只存放了user.id
        ctx.res = ctx.format_res(
            create_access_token(user.username, expires_delta=access_token_expires),
        )

    return ctx.res


@app.get('/api/conf/genFile/{conf_group_uuid}')
async def gen_file(
        req: fastapi.Request,
        conf_group_uuid: str,
        db_pri: Session_secret = fastapi.Depends(get_db_secret)):
    async with AuditWithExceptionContextManager(db_pri, req, a_cls=modelsecret.Audit) as ctx:
        res = db_pri.query(modelsecret.ConfGroup).filter(modelsecret.ConfGroup.uuid == conf_group_uuid).all()[0]
        base_url = str(req.base_url).replace('http://', '').replace('/', '') + f':{default.WEB_PORT}'
        project = res.project_name
        env = res.environment_name
        pub_key = res.key_pub
        pub_key_raw = res.key_pub.replace("\n", '').split(
            '-----BEGIN RSA PRIVATE KEY-----')[-1].split('-----END RSA PRIVATE KEY-----')[0]
        pri_key = res.key_pri
        pri_key_raw = res.key_pri.replace("\n", '').split(
            '-----BEGIN PUBLIC KEY-----')[-1].split('-----END PUBLIC KEY-----')[0]
        ver = res.ver
        data = await get_req_data(req)
        package_key = data.get('package_key', 'conftab')
        java_code = f"""{package_key}.config.conftab.server=http://{base_url}/api/conf/get?project={project}&env={env}&ver={ver}&key=ALL
{package_key}.config.conftab.rsaPrivateKey={pri_key_raw}
{package_key}.config.conftab.signPublicKey={pub_key_raw}
"""
        python_code = f"""import json
import conftab
CT = json.loads(conftab.Tab(
    '{base_url}',
    project='{project}', env='{env}', ver='{ver}',
    key_pub='''{pub_key}''',
    key_pri='''{pri_key}'''
).dict().get('ALL', '{{}}'))
# 列出全部配置，变成字典方便调用
print(f'当前配置为{{type(CT), CT}}')
"""
        json_code = res.value_raw
        ctx.res = ctx.format_res('成功', {
            "java_code": java_code,
            "python_code": python_code,
            "json_code": json_code,
        })
    return ctx.res


@app.get('/api/conf/saveFromDB/{conf_group_uuid}')
async def save_conf(
        req: fastapi.Request,
        conf_group_uuid: str,
        db_pub: Session = fastapi.Depends(get_db),
        db_pri: Session_secret = fastapi.Depends(get_db_secret)):
    async with AuditWithExceptionContextManager(db_pub, req, a_cls=model.Audit) as ctx_pub:
        async with AuditWithExceptionContextManager(db_pri, req, a_cls=modelsecret.Audit) as ctx_pri:
            res = db_pri.query(modelsecret.ConfGroup).filter(modelsecret.ConfGroup.uuid == conf_group_uuid).all()
            if len(res) == 1:
                rsa_c = RSACtrl().load_or_generate_key(2048)
                conf_group = res[0]
                conf_value = json.dumps({
                    cell['data']['key']: cell['data']['value']
                    for cell in json.loads(conf_group.value)['cells']
                    if ((not cell.get('data', {}).get('parent')) and cell.get('data', {}).get('key'))
                })
                conf_group = conf_group.update_self(
                    value_raw=conf_value,
                    value_secret=rsa_c.encode(conf_value),
                    key_pub=rsa_c.public_key.decode(),
                    key_pri=rsa_c.private_key.decode(),
                )
                conf_group_dict = conf_group.to_dict()
                db_pri.merge(conf_group)
                db_pri.commit()

                conf_dict = {k: v for k, v in conf_group_dict.items()}
                conf_dict['value'] = conf_group_dict['value_secret']
                conf_dict['project'] = conf_group_dict['project_name']
                conf_dict['env'] = conf_group_dict['environment_name']
                conf_dict['key'] = 'ALL'
                c = Conf().update_self(**conf_dict)
                conf_dict = c.to_dict()
                db_pub.merge(c)
                db_pub.commit()
                ctx_pri.res = ctx_pri.format_res('变更密钥成功', {'data': {
                    'conf_group': conf_group_dict,
                    'conf': conf_dict
                }})
            else:
                ctx_pri.res = ctx_pri.format_res('conf_group uuid 不存在', suc=False)
    return ctx_pri.res


@app.get('/api/conf/get')
async def get_conf(req: fastapi.Request, db: Session = fastapi.Depends(get_db)):
    logging.info(f'{dict(req.items())}')
    async with AuditWithExceptionContextManager(db, req, a_cls=model.Audit) as ctx:
        data = await get_req_data(req)
        res = db.query(Conf).filter(*(getattr(
            Conf, k) == v for k, v in data.items())).order_by(desc(Conf.timeupdate)).limit(2).all()
        if len(res) == 1:
            if 'private_key' in data:
                res[0].value = RSACtrl(private_key=data.pop('private_key')).decode(res[0].value)
            ctx.res = {'data': res[0].value, "raw": res, "res_raw": res[0]}
        elif len(res) > 1:
            ctx.res = {'data': None, 'err': '配置超过两个，请检查', "raw": res, "res_raw": res[0]}
        else:
            ctx.res = {'data': None, 'raw': [], 'res_raw': {}}
    return ctx.res


@app.get('/api/conf/list')
async def list_conf(req: fastapi.Request, db: Session = fastapi.Depends(get_db)):
    async with AuditWithExceptionContextManager(db, req, a_cls=model.Audit) as ctx:
        data = await get_req_data(req)
        res = db.query(Conf).filter(*(getattr(Conf, k) == v for k, v in data.items())).all()
        ctx.res = [d.to_dict() for d in res]
    return ctx.res


@app.post('/api/conf/set')
async def set_conf(req: fastapi.Request, db: Session = fastapi.Depends(get_db)):
    logging.info(f'{dict(req.items())}')
    async with AuditWithExceptionContextManager(db, req, a_cls=model.Audit) as ctx:
        data = await get_req_data(req)
        if 'public_key' in data:
            data['value'] = RSACtrl(public_key=data.pop('public_key')).encode(data['value'])
        c = Conf(**data)
        # c.uuid = f'{c.project}--{c.env}--{c.ver}--{c.key}--{c.value}'
        c.uuid = f'{c.project}--{c.env}--{c.ver}--{c.key}'
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
        cls = item_clss_secret[item_name]
        res = db.query(cls).filter(*(getattr(cls, k) == v for k, v in data.items())).order_by(
            desc(Conf.timecreate)).limit(2).all()
        if len(res) == 1:
            ctx.res = {'data': getattr(builtins, res[0].value_type)(
                res[0].value) if res[0].value_type in dir(builtins) else res[0].value, "raw": res, "res_raw": res[0]}
        elif len(res) > 1:
            ctx.res = {'data': None, 'err': '配置超过两个，请检查', "raw": res, "res_raw": res[0]}
        else:
            ctx.res = {'data': None, "raw": [], "res_raw": {}}
    return ctx.res


class ListItemParam(BaseModel):
    # uuid: str = Field(..., description="表名称", example="task")
    page: int = Field(..., description="页码", example=1)
    pageSize: int = Field(..., description="页面大小", example=20)
    filters: list = Field({}, description="过滤查询，完全匹配，K-V对list", example=[{
        'key': 'environment_name',
        "value": "",
        'like': False,
    }])
    sort: list = Field({}, description="排序", example=[{
        'key': 'environment_name',
        'value': 'asc',
    }, {
        'key': 'time_update',
        'value': 'desc',
    }])
    tableInfo: bool = Field(False, description="是否返回表信息", example=False)


@app.post('/api/{db_name}/{item_name}/list')
async def list_item(
        item_name, body: ListItemParam,
        req: fastapi.Request,
        db_name: str,
        db_c: Session_secret = fastapi.Depends(get_db),
        db_secret: Session_secret = fastapi.Depends(get_db_secret)):
    if db_name == 'secretItem':
        db = db_secret
        a_cls = modelsecret.Audit
        item_clss = item_clss_secret
    elif db_name == 'publicItem':
        db = db_c
        a_cls = model.Audit
        item_clss = item_clss_pub
    else:
        db = db_c
        a_cls = model.Audit
        item_clss = item_clss_pub
    async with AuditWithExceptionContextManager(db, req, a_cls=a_cls) as ctx:
        data = await get_req_data(req)
        if "pageSize" in data:
            limit = int(data.pop('pageSize'))
            if "page" in data:
                offset = max(0, int(data.pop('page')) - 1) * limit
            else:
                offset = 0
        else:
            limit, offset = 0, 0
        cls = item_clss[item_name]

        ftr_d = []
        for fd in data.get('filters', []):
            f_nk, f_v, like = fd['key'], fd['value'], fd.get('like')
            if "___" in f_nk:
                ftr_table_name, f_k = f_nk.split('___')
            else:
                ftr_table_name, f_k = item_name, f_nk
            # ftr_table_cls = getattr(models, "".join(s.capitalize() for s in ftr_table_name.split('_')))
            if like:
                ftr_d.append(
                    func.cast(getattr(cls, f_k), TEXT()) == f_v if not isinstance(
                        f_v, str) else func.cast(getattr(cls, f_k), TEXT()).like(f"%{f_v}%"))
            else:
                ftr_d.append(func.cast(getattr(cls, f_k), TEXT()) == f_v)

        query_d = db.query(cls).filter(
            *ftr_d
            # *(getattr(cls, flr['key']) == flr['value'] for flr in data.get('filters', []))
        )
        sql_code = str(query_d)
        total = query_d.count()
        if sort := data.get('sort'):
            query_d = query_d.order_by(
                *(getattr(getattr(cls, flr['key']), flr['value'])()
                  for flr in sort if flr['value'].lower() in ['desc', 'asc']))
        if offset:
            query_d = query_d.offset(offset)
        if limit:
            query_d = query_d.limit(limit)

        res = [d.to_dict() for d in query_d.all()]
        ctx.res = {
            "server_time": time.time(),
            "data": res,
            "sql_code": sql_code,
            "total": total,
        }
        if body.tableInfo:
            ctx.res["table_info"] = cls.get_columns_infos()
    return ctx.res


@app.post('/api/secretItem/{item_name}')
async def set_conf(item_name, req: fastapi.Request, db: Session_secret = fastapi.Depends(get_db_secret)):
    async with AuditWithExceptionContextManager(db, req, a_cls=modelsecret.Audit) as ctx:
        data = await get_req_data(req)
        cls = item_clss_secret[item_name]
        cls_info = cls.get_columns_info()
        data_kvs = {k: change_type[cls_info[k]['type_str'][:4]](v) for k, v in data.items()}
        c = cls(**data_kvs).update_self(**data_kvs)
        db.merge(c)
        db.commit()
        ctx.res = ctx.format_res(c.to_dict())
    return ctx.res


@app.delete('/api/secretItem/{item_name}')
async def del_item(item_name, body: ListItemParam,
                   req: fastapi.Request, db: Session_secret = fastapi.Depends(get_db_secret)):
    async with AuditWithExceptionContextManager(db, req, a_cls=modelsecret.Audit) as ctx:
        data = await get_req_data(req)
        if "pageSize" in data:
            limit = int(data.pop('pageSize'))
            if "page" in data:
                offset = max(0, int(data.pop('page')) - 1) * limit
            else:
                offset = 0
        else:
            limit, offset = 0, 0
        cls = item_clss_secret[item_name]
        query_d = db.query(cls).filter(
            *(getattr(cls, flr['key']) == flr['value']
              for flr in data.get('filters', []))
        )
        if offset:
            query_d = query_d.offset(offset)
        if limit:
            query_d = query_d.limit(limit)
        res = []
        for d in query_d.all():
            res.append(d.to_dict())
            db.delete(d)
            db.commit()
        ctx.res = {
            "server_time": time.time(),
            "data": res,
            "total": len(res)
        }
    return ctx.res


class ListItemPKParam(BaseModel):
    # uuid: str = Field(..., description="表名称", example="task")
    pks: list = Field(..., description="过滤查询，完全匹配，K-V对list", example=[
        '1', 2, '3'
    ])


@app.delete('/api/secretItemByPK/{item_name}')
async def del_item_pk(
        item_name, body: ListItemPKParam,
        req: fastapi.Request, db: Session_secret = fastapi.Depends(get_db_secret)):
    async with AuditWithExceptionContextManager(db, req, a_cls=modelsecret.Audit) as ctx:
        cls = item_clss_secret[item_name]
        res = []
        for pk in body.pks:
            pk_keys = cls.get_primary_keys()
            for d in db.query(cls).filter(
                    *(getattr(cls, pk_key) == pk
                      for pk_key in pk_keys)
            ).all():
                res.append(d.to_dict())
                db.delete(d)
                db.commit()
        ctx.res = {
            "server_time": time.time(),
            "data": res,
            "total": len(res)
        }
    return ctx.res


class SetConfItemParam(BaseModel):
    # uuid: str = Field(..., description="表名称", example="task")
    environment_name: str = Field(..., description="环境名", example="task")
    environment_type: str = Field(..., description="环境类型", example="task")
    project_name: str = Field(..., description="名", example="task")
    project_type: str = Field(..., description="类型", example="task")
    ver: str = Field(..., description="版本", example="task")
    owner: str = Field(..., description="编辑者", example="task")
    key: str = Field(None, description="配置KEY", example="task")
    value: str = Field(None, description="配置value", example="task")
    value_type: str = Field(None, description="配置value类型", example="task")
    kvs: list = Field([], description="配置kvs类型", example=[
        {
            'key': 'ES_HOST',
            'value': '127.0.0.1',
            'value_type': 'str',
        },{
            'key': 'ES_PORT',
            'value': '9200',
            'value_type': 'int',
        }
    ])
    host_name: str = Field(..., description="配置value所在机器host", example="task")
    port: str = Field(..., description="配置value所在机器服务port", example="")
    server_name: str = Field(..., description="配置value所在机器服务名称", example="task")
    server_type: str = Field('', description="配置value所在机器服务类型", example="es")
    username: str = Field('', description="配置value所在机器服务用户名", example="")
    password: str = Field('', description="配置value所在机器服务密码", example="")
    device_name: str = Field('', description="配置value所在机器名称", example="es.node1")
    device_type: str = Field('', description="配置value所在机器类型", example="es")
    ssh_ip: str = Field('', description="配置value所在机器ip", example="task")
    ssh_port: str = Field('', description="配置value所在机器ssh端口", example="task")
    ssh_username: str = Field('', description="配置value所在机器ssh用户名", example="task")
    ssh_password: str = Field('', description="配置value所在机器ssh密码", example="task")


@app.post('/api/secretItemAuto/confItem')
async def set_conf_item(body: SetConfItemParam, req: fastapi.Request,
                        db: Session_secret = fastapi.Depends(get_db_secret)):
    async with AuditWithExceptionContextManager(db, req, a_cls=modelsecret.Audit) as ctx:
        data_kvs = await get_req_data(req)
        if data_kvs.get('kvs'):
            kvs = data_kvs.get('kvs')
        else:
            kvs = [{
                'key': data_kvs.get('key'),
                'value': data_kvs.get('value'),
                'value_type': data_kvs.get('value_type'),
            }]

        data = {k: v for k, v in data_kvs.items()}
        for kv in kvs:
            data['key'] = kv['key']
            data['value'] = kv['value']
            data['value_type'] = kv['value_type']
            for item in [
                modelsecret.ConfItem().update_self(**data),
                modelsecret.Project().update_self(**data),
                modelsecret.Environment().update_self(**data),
                modelsecret.ServerConfItem().update_self(**data),
                modelsecret.Server().update_self(**data),
            ]:
                # c.uuid = f'{c.project}--{c.env}--{c.ver}--{c.key}--{c.value}'
                db.merge(item)
                db.commit()
            if all(key in data for key in [
                "server_name",
                "device_name",
            ]):
                for item in [
                    modelsecret.ServerDevice().update_self(**data),
                    modelsecret.Device().update_self(**data)
                ]:
                    # c.uuid = f'{c.project}--{c.env}--{c.ver}--{c.key}--{c.value}'
                    db.merge(item)
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
        return "无此表格，请在</br>{}</br>中选择".format(
            '</br>'.join(f'<a href="/html/secret/{key}">{key}</a>' for key in item_clss_secret.keys())
        )
    res = list(d.to_dict()
               for d in db.query(cls).filter(*(getattr(cls, k) == v for k, v in data.items())).all()
               )
    return format_to_form(f"/api/secretItem/{item_name}", cls.get_columns_infos()) + format_to_table(
        res, keys=cls.get_columns())
