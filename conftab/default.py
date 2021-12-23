WEB_HOST = '127.0.0.1'
WEB_PORT = 7788

PROJECT_NAME = 'default'

ENV = 'dev'

VERSION = '1.0.0'

# SQLALCHEMY_DATABASE_URL: str = 'sqlite:///:memory:'
SQLALCHEMY_DATABASE_URL: str = 'sqlite:///conftab.db'


def set_url(url):
    global SQLALCHEMY_DATABASE_URL
    SQLALCHEMY_DATABASE_URL = url
