import requests
import builtins
from conftab.default import WEB_HOST, WEB_PORT, PROJECT_NAME, ENV, VERSION


def get_conf(
        key, default=None, manager_url=f'{WEB_HOST}:{WEB_PORT}',
        project=PROJECT_NAME, env=ENV, ver=VERSION, rsa_ctrl=None):
    res = requests.get(f'http://{manager_url}/api/conf/get', data={
        'project': project,
        'env': env,
        'ver': ver,
        'key': key,
    }).json().get('res_raw')
    if not res:
        result = default
    else:

        if rsa_ctrl:
            res['value'] = rsa_ctrl.decode(res['value'])
        result = getattr(builtins, res['value_type'])(
            res['value']) if res['value_type'] in dir(builtins) else res['value']
    return result


def list_conf(manager_url=f'{WEB_HOST}:{WEB_PORT}', project=PROJECT_NAME,
              env=ENV, ver=VERSION, to_dict=True, rsa_ctrl=None):
    res = requests.get(f'http://{manager_url}/api/conf/list', data={
        'project': project,
        'env': env,
        'ver': ver,
    }).json()
    if to_dict:
        result = {}
        for d in res:
            if rsa_ctrl:
                d["value"] = rsa_ctrl.decode(d["value"])
            result[d["key"]] = getattr(builtins, d['value_type'])(
                d["value"]) if d['value_type'] in dir(builtins) else d["value"]
        return result
    else:
        if rsa_ctrl:
            for d in res:
                d["value"] = rsa_ctrl.decode(d["value"])
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


def gen_key():
    # TODO 注册一个密钥
    pass


def get_key(path):
    # TODO 注册并获取密钥保存到本地文件路径
    pass

if __name__ == '__main__':
    print(set_conf('es_port', 9200))
    print(list_conf())
    print(get_conf('es_port'))
