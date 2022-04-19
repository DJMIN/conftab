import datetime


class Mixin:
    def __init__(self, **kwargs):
        self.update_self(**kwargs)

    def get_uuid_key(self):
        return 'uuid'

    def gen_uuid(self):
        return f''

    def set_uuid(self):
        uuid_key = self.get_uuid_key()
        if uuid_key in self.get_columns():
            setattr(self, uuid_key, self.gen_uuid())

    def set_time(self):
        time_now = datetime.datetime.now()
        if 'timecreate' in self.get_columns() and not getattr(self, 'timecreate', None):
            setattr(self, 'timecreate', time_now.timestamp())
            setattr(self, 'time_create', time_now)
        if 'timeupdate' in self.get_columns():
            setattr(self, 'timeupdate', time_now.timestamp())
            setattr(self, 'time_update', time_now)

    def update_self(self, **kwargs):
        cols = self.get_columns()
        for k, v in kwargs.items():
            if k in cols:
                setattr(self, k, v)

        self.set_uuid()
        self.set_time()
        return self

    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in getattr(self, "__table__").columns}

    @classmethod
    def get_columns(cls):
        return [c.name for c in getattr(cls, "__table__").columns]

    @classmethod
    def get_primary_keys(cls):
        return [c.name for c in getattr(cls, "__table__").columns if c.primary_key]

    @classmethod
    def get_columns_infos(cls):
        return [{
            "name": c.name,
            "primary_key": c.primary_key,
            # "type": c.type,
            "type_str": str(c.type),
            "nullable": c.nullable,
            "comment": c.comment
        } for c in getattr(cls, "__table__").columns]

    @classmethod
    def get_columns_info(cls):
        return {c['name']: c for c in cls.get_columns_infos()}
