WEB_HOST = '127.0.0.1'
WEB_PORT = 7788

PROJECT_NAME = 'default'

ENV = 'dev'

VERSION = '1.0.0'

# SQLALCHEMY_DATABASE_URL: str = 'sqlite:///:memory:'
SQLALCHEMY_DATABASE_URL: str = 'sqlite:///conftab.db'
SQLALCHEMY_DATABASE_URL_SECRET: str = 'sqlite:///conftab_secret.db'

PUBKEY_PATH: str = './server_key_pub.key'
PRIKEY_PATH: str = './server_key_pri.key'


def set_web_port(port):
    global WEB_PORT
    WEB_PORT = port


def set_url(url):
    global SQLALCHEMY_DATABASE_URL
    SQLALCHEMY_DATABASE_URL = url


def set_url_secret(url):
    global SQLALCHEMY_DATABASE_URL_SECRET
    SQLALCHEMY_DATABASE_URL_SECRET = url
