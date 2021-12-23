import requests
import builtins
from conftab.default import WEB_HOST, WEB_PORT, PROJECT_NAME, ENV, VERSION


def get_conf(key, default=None, manager_url=f'{WEB_HOST}:{WEB_PORT}', project=PROJECT_NAME, env=ENV, ver=VERSION):
    res = requests.get(f'http://{manager_url}/api/conf/get', data={
        'project': project,
        'env': env,
        'ver': ver,
        'key': key,
    }).json().get('data')
    if res is None:
        res = default
    return res


def list_conf(manager_url=f'{WEB_HOST}:{WEB_PORT}', project=PROJECT_NAME, env=ENV, ver=VERSION, to_dict=True):
    res = requests.get(f'http://{manager_url}/api/conf/list', data={
        'project': project,
        'env': env,
        'ver': ver,
    }).json()
    if to_dict:
        result = {}
        for d in res:
            result[d["key"]] = getattr(builtins, d['value_type'])(d["value"])
        return result
    else:
        return res


def set_conf(key, value, manager_url=f'{WEB_HOST}:{WEB_PORT}', project=PROJECT_NAME, env=ENV, ver=VERSION):
    return requests.post(f'http://{manager_url}/api/conf/set', data={
        'project': project,
        'env': env,
        'ver': ver,
        'key': key,
        'value': value,
        'value_type': type(value).__name__,
    }).json()


if __name__ == '__main__':
    print(set_conf('es_port', 9200))
    print(list_conf())
    print(get_conf('es_port'))
