import builtins
import datetime
import time

import fastapi
import logging
from conftab.model import get_db, Server, Conf, Session
from conftab.default import SQLALCHEMY_DATABASE_URL
from sqlalchemy import desc


app = fastapi.FastAPI()


@app.get('/')
async def index(req: fastapi.Request):
    return {"server": 'conftab', "msg": "hello! http://127.0.0.1:7788/html/conf", "db": SQLALCHEMY_DATABASE_URL,
            'server_time': time.time()}


@app.get('/api/conf/get')
async def get_conf(req: fastapi.Request, db: Session = fastapi.Depends(get_db)):
    logging.info(f'{dict(req.items())}')
    data = (dict(await req.form()))
    res = db.query(Conf).filter(*(getattr(Conf, k) == v for k, v in data.items())).order_by(desc(Conf.timecreate)).limit(1).all()
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
    data = (dict(await req.form()))
    res = db.query(Conf).filter(*(getattr(Conf, k) == v for k, v in data.items())).all()
    return res


@app.post('/api/conf/set')
async def set_conf(req: fastapi.Request, db: Session = fastapi.Depends(get_db)):
    logging.info(f'{dict(req.items())}')
    data = (dict(await req.form()))
    c = Conf(**data)
    c.uuid = f'{c.project}--{c.env}--{c.ver}--{c.key}--{c.value}'
    c.timecreate = time.time()
    c.time_create = datetime.datetime.now()
    db.merge(c)
    db.commit()
    return


def format_to_table(data, keys=None, pk='id'):
    if not data:
        return '表格无数据'
    if not keys:
        keys = set()
        for d in data:
            for k, v in d.items():
                keys.add(k)
        keys = list(keys)
        keys.sort()
        # noinspection PyBroadException
        try:
            keys.remove(pk)
            keys.append(pk)
            keys.reverse()
        except Exception:
            pass
    return """
    <style> 
    table td{border:1px solid #F00} 
    </style>""" + """
    <table>
    <tr>
        {}
    </tr>""".format(
        ''.join(f"<th>{k}</th>" for k in keys)) + ''.join("""
    <tr>
        {}
    </tr>""".format(
        ''.join("<td>{}</td>".format(d.get(k, '/')) for k in keys)) for d in data) + """
    </table>"""


@app.get('/html/conf', response_class=fastapi.responses.HTMLResponse)
async def html_list_conf(req: fastapi.Request, db: Session = fastapi.Depends(get_db)):
    data = (dict(req.query_params))
    res = list(d.to_dict() for d in db.query(Conf).filter(*(getattr(Conf, k) == v for k, v in data.items())).all())
    return format_to_table(
        res,
        keys=['project', 'env', 'ver', 'time_create', 'time_update', 'value_type', 'key', 'value'])
