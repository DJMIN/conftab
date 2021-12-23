from conftab.function import get_conf, list_conf, set_conf
from conftab.default import WEB_HOST, WEB_PORT, PROJECT_NAME, ENV, VERSION


class Tab:
    def __init__(self, manager_url=f"{WEB_HOST}:{WEB_PORT}", project=PROJECT_NAME, env=ENV, ver=VERSION):
        if len(ms := manager_url.split(':')) < 2:
            self.host = ms[0]
            self.port = 7788
        else:
            self.host = ms[0]
            self.port = ms[-1]
        self.manager_url = f"{self.host}:{self.port}"
        self.project = project
        self.env = env
        self.ver = ver

    def get(self, key, default=None):
        res = get_conf(
            key, default=default, manager_url=self.manager_url, project=self.project, env=self.env, ver=self.ver)
        return res

    def list(self):
        return list_conf(
            manager_url=self.manager_url, project=self.project, env=self.env, ver=self.ver, to_dict=False)

    def dict(self):
        return list_conf(
            manager_url=self.manager_url, project=self.project, env=self.env, ver=self.ver, to_dict=True)

    def set(self, key, value):
        return set_conf(key, value, manager_url=self.manager_url, project=self.project, env=self.env, ver=self.ver)
