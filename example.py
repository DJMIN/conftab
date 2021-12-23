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
