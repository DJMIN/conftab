import sys
import os
import json.decoder


async def get_req_data(req, get_json=True, raise_err=False):
    data = dict(req.query_params)

    try:
        data_json = dict(await req.json()) if get_json and (req.method.upper() not in ['get']) else {}
    except json.decoder.JSONDecodeError:
        data_json = {}
        if raise_err:
            raise

    data = data | dict(await req.form() or {}) | data_json
    return data


def format_to_form(action, keys):
    return '''
        <form action="{}" method="POST">
            <table>
                {}<input type="submit" value="添加一条数据">
            </table>
        </form>
        '''.format(
        action,
        ''.join(
            f"""<tr>
            <td style="width:13%;" >{key['name']}</td>
            <td style="width:7%;" >主键：{key['primary_key']}</td>
            <td style="width:15%;" >{key['type_str']}</td>
            <td style="width:15%;" >注释：{key['comment']}</td>
            <td><input style="width:100%;" type="text" name="{key['name']}"></td></tr>"""
            for key in keys
        )
    )


def format_to_table(data, keys=None, pk='id'):
    if not data:
        return '表格无数据'
    if not keys:
        keys = set()
        for d in data:
            for k, v in d.items():
                keys.add(k)
        keys = list(keys)
        keys.sort()
        # noinspection PyBroadException
        try:
            keys.remove(pk)
            keys.append(pk)
            keys.reverse()
        except Exception:
            pass
    return """
    <style> 
    table{
        width:100%;
        table-layout: fixed;
    } 
    table td {
        border:1px solid #F00;
    }
    table td div{
        work-wrap: break-word;
        word-break: break-all;
        max-height: 77px;
        height: 100%;
        overflow: overlay;
    } 
    
    div::-webkit-scrollbar{ //设置整个滚动条宽高
      width:3px;
      height:100%;
    }
    div::-webkit-scrollbar-thumb{ //设置滑块
      width:3px;
      height:3px;
      background-color:rgba(77,77,77,.3);
      border-radius:1px;
    }
    div::-webkit-scrollbar-track 
    { 
      border-radius: 1px; 
      background-color: rgba(127,127,127,.3);  //设置背景透明
    }
    </style>""" + """
    <table>
    <tr>
        {}
    </tr>""".format(
        ''.join(f"<th>{k}</th>" for k in keys)) + ''.join("""
    <tr>
        {}
    </tr>""".format("".join("<td><div>{}</div></td>".format(d.get(k, '/')) for k in keys)) for d in data) + """
    </table>"""


def get_realpath_here(file_path=None, with_lineno=False):
    if not file_path:
        sys_g = getattr(sys, '_getframe')
        _line = sys_g().f_back.f_lineno  # 调用此方法的代码的函数
        file_path = sys_g(1).f_code.co_filename  # 哪个文件调了用此方法
    else:
        _line = 1
    return f' "{file_path}:{_line}" ' if with_lineno else os.path.split(os.path.realpath(file_path))[0]
