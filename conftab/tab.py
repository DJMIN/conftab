from conftab.function import get_conf, list_conf, set_conf, clean_log, get_log
from conftab.default import WEB_HOST, WEB_PORT, PROJECT_NAME, ENV, VERSION
from conftab.cyhper import RSACtrl


class Tab:
    def __init__(
            self, manager_url=f"{WEB_HOST}:{WEB_PORT}", project=PROJECT_NAME,
            env=ENV, ver=VERSION, key_pub='', key_pri=''):
        if len(ms := manager_url.split(':')) < 2:
            self.host = ms[0]
            self.port = 7788
        else:
            self.host = ms[0]
            self.port = ms[-1]
        self.host = self.host.replace(r'http://', '')
        self.port = self.port.replace('/', '')
        self.manager_url = f"{self.host}:{self.port}"
        self.project = project
        self.env = env
        self.ver = ver

        if key_pub:
            if key_pub.startswith('-----BEGIN '):
                public_key = key_pub
                publickey_path = None
            else:
                public_key = None
                publickey_path = key_pub
            self.can_encrypt = True

        else:
            public_key = None
            publickey_path = None
            self.can_encrypt = False
        if key_pri:
            if key_pri.startswith('-----BEGIN '):
                private_key = key_pri
                privatekey_path = None
            else:
                private_key = None
                privatekey_path = key_pri
            self.can_decipher = True
        else:
            private_key = None
            privatekey_path = None
            self.can_decipher = False
        self.rsa_ctrl = RSACtrl(
            private_key=private_key, public_key=public_key,
            privatekey_path=privatekey_path, publickey_path=publickey_path
        ).load_or_generate_key(2048)

    def get(self, key, default=None):
        if self.can_decipher:
            res = get_conf(
                key, default=default, manager_url=self.manager_url,
                project=self.project, env=self.env, ver=self.ver, rsa_ctrl=self.rsa_ctrl)
        else:
            res = get_conf(
                key, default=default, manager_url=self.manager_url,
                project=self.project, env=self.env, ver=self.ver)
        return res

    def list(self):
        if self.can_decipher:
            res = list_conf(
                manager_url=self.manager_url, project=self.project,
                env=self.env, ver=self.ver, to_dict=False, rsa_ctrl=self.rsa_ctrl)
        else:
            res = list_conf(
                manager_url=self.manager_url, project=self.project, env=self.env, ver=self.ver, to_dict=False)
        return res

    def dict(self):
        if self.can_decipher:
            res = list_conf(manager_url=self.manager_url, project=self.project,
                            env=self.env, ver=self.ver, to_dict=True, rsa_ctrl=self.rsa_ctrl)
        else:
            res = list_conf(
                manager_url=self.manager_url, project=self.project, env=self.env, ver=self.ver, to_dict=True)
        return res

    def set(self, key, value):
        if self.can_encrypt:
            value = self.rsa_ctrl.encode(value)
        return set_conf(key, value, manager_url=self.manager_url, project=self.project, env=self.env, ver=self.ver)

    def get_log(self, page_size=1, page=10, **kwargs):
        return get_log(manager_url=self.manager_url, page_size=page_size, page=page, **kwargs)

    def clean_log(self):
        return clean_log(manager_url=self.manager_url)
