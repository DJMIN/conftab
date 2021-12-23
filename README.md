# conftab
# config table 

配置web版本管理系统
config version manager with web or code easily

## RUN

1. 服务端： 启动web管理界面
```shell script
pip install conftab

# 运用sqlite数据库，-f指定配置数据的保存文件位置，-p指定
python -m conftab.ctl run -p 7788 -f './conftab.db'

# 浏览器可以访问 http://127.0.0.1:7788/html/conf 
# 进行界面config管理
```

2. 客户端： 项目通过接口在线取config配置
```python
import conftab

CONFIG = conftab.Tab(project='default', env='dev', ver='1.0.0', manager_url='127.0.0.1:7788')

# 设置
CONFIG.set('ES_PORT', 9200)    # （可以在代码里也可以在web界面里去调整）

# 获取
ES_PORT = CONFIG.get('ES_PORT')

```

```python
import conftab
import multiprocessing
import time
import requests

# 启动服务
multiprocessing.Process(target=conftab.run_app, args=('0.0.0.0', 7788)).start()

# 等待初始化服务
time.sleep(2)

# 初始化客户端服务
conft = conftab.Tab('127.0.0.1:7788',  project='xxx', env='dev', ver='v1.0.1')

# 客户端取不存在的配置
print(conft.get('es_port', 9201))

# 设置配置，客户端通过代码设置配置，这部分可以通过web界面来管理设计
conft.set('es_port', 9200)

# 客户端取存在的配置
print(conft.get('es_port', 9201))

# 客户端列出全部配置，变成列表
print(conft.list(to_dict=False))

# 客户端列出全部配置，变成字典方便调用
print(conft.list(to_dict=True))

# 客户端通过web浏览器管理曾经全部的配置
print(requests.get('http://127.0.0.1:7788/html/conf').text)

```

TODO list

1. web manager
2. server manager
