# conftab
# config table 

配置web版本管理系统（config version manager with web or code easily）
作为开发人员，经常会涉及到环境部署，一些数据库地址帐号密码配置我们不希望硬编码在项目文件里，再被一不小心提交到代码仓库再开源出去，所以，需要在内网环境部署一套配置管理系统。这样项目中再连接这个管理地址取到相应的配置，可以方便部署和管理环境配置又不用担心重要的信息泄露出去。


## RUN

1. 服务端： 启动web管理界面和接口
```shell script
pip install conftab

# 运用sqlite数据库，-f指定配置数据的保存文件位置，方便备份和加密迁移，-p指定服务端的监听端口
python -m conftab.ctl run -p 7788 -f './conftab.db'

# 如果想要后台长期启动，可以利用nohup，并将日志写入conftab.log文件
nohup python3.9 -m conftab.ctl run -p 7788 -h "0.0.0.0" -f './conftab.db' > conftab.log 2>&1 &

```

2. 客户端： 项目通过接口在线取config配置
```python
import conftab

CONFIG = conftab.Tab(project='default', env='dev', ver='1.0.0', manager_url='127.0.0.1:7788')

# 设置
CONFIG.set('ES_PORT', 9200)    # 可以在代码里也可以在web界面里去调整，浏览器访问 http://127.0.0.1:7788/html/conf 进行界面config管理

# 获取
ES_PORT = CONFIG.get('ES_PORT')

# 批量获取
conf = CONFIG.dict()  # 一次性获取该项目全部配置dict，减少http请求
ES_PORT = conf.get('ES_PORT')
```

更多详细可见 example.py 文件

# TODO list

1. web manager
2. server manager
