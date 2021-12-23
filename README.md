# conftab
# config table 

配置web版本管理系统（config version manager with web or code easily）


## RUN

1. 服务端： 启动web管理界面和接口
```shell script
pip install conftab

# 运用sqlite数据库，-f指定配置数据的保存文件位置，-p指定
python -m conftab.ctl run -p 7788 -f './conftab.db'
```

2. 客户端： 项目通过接口在线取config配置
```python
import conftab

CONFIG = conftab.Tab(project='default', env='dev', ver='1.0.0', manager_url='127.0.0.1:7788')

# 设置
CONFIG.set('ES_PORT', 9200)    # （可以在代码里也可以在web界面里去调整）浏览器可以访问 http://127.0.0.1:7788/html/conf 进行界面config管理

# 获取
ES_PORT = CONFIG.get('ES_PORT')

# 批量获取
conf = CONFIG.list()  # 一次性获取该项目全部配置dict，减少http请求
ES_PORT = conf.get('ES_PORT')
```

更多详细可见 example.py 文件

# TODO list

1. web manager
2. server manager
