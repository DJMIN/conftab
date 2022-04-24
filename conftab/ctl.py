import click
import uvicorn
import socket
import os
from conftab.default import WEB_PORT, WEB_HOST, set_web_port


def run_app(host, port):
    from uvicorn.config import LOGGING_CONFIG
    from conftab.web import app

    # LOGGING_CONFIG['incremental'] = True
    # LOGGING_CONFIG['disable_existing_loggers'] = True
    # LOGGING_CONFIG["loggers"]["watchman"] = {"handlers": ["default"], "level": "INFO"}
    LOGGING_CONFIG["loggers"]["uvicorn"]["propagate"] = False
    LOGGING_CONFIG["formatters"]["default"][
        "fmt"] = '[%(levelprefix)s][%(asctime)s][%(name)s] "%(pathname)s:%(lineno)d" %(message)s'
    LOGGING_CONFIG["formatters"]["access"][
        "fmt"] = '[%(levelprefix)s][%(asctime)s][%(name)s] [%(client_addr)s] "%(request_line)s" %(status_code)s'
    set_web_port(port)
    uvicorn.run(app=app, host=host, port=port, workers=1, debug=True, log_config=LOGGING_CONFIG)


@click.group()
def ctl():
    pass


@click.command()
@click.option('-h', '--host', default="0.0.0.0", help='web管理端绑定host')
@click.option('-p', '--port', default=WEB_PORT, help='web管理端绑定端口号')
@click.option('-f', '--file', default="./conftab.db", help='web管理端sqlite数据库存储位置路径')
def run(host, port, file):
    """web manager runner"""
    file_path = os.path.realpath(file)

    from conftab.default import set_url
    set_url(f'sqlite:///{file_path}')

    from conftab.model import init_db
    from conftab.modelsecret import init_db as init_db_secret
    init_db()
    init_db_secret()

    click.echo(f'start manager: {host}:{port} db路径: {file_path}')
    # sockobj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockobj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockobj.settimeout(3)
    # sockobj.bind((host, port))
    result = sockobj.connect_ex(('127.0.0.1', port))
    if result == 0:
        click.echo(result)
        raise SystemError('端口被占用了')
    run_app(host, port)


ctl.add_command(run)


if __name__ == '__main__':
    ctl()
