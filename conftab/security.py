from datetime import datetime, timedelta
from typing import Any, Union, Optional
from jose import jwt
from fastapi import Header, Query
from random import sample

# 导入配置文件

ALGORITHM = "HS256"
SECRET_KEY = ''.join([sample("abcdefghijklmnopqrstuvwxyz", 1)[0] for _ in range(32)])
ACCESS_TOKEN_EXPIRE_MINUTES = 86400


def create_access_token(
        subject: Union[str, Any], expires_delta: timedelta = None
) -> str:
    """
    # 生成token
    :param subject: 保存到token的值
    :param expires_delta: 过期时间
    :return:
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode = {"exp": expire, "sub": str(subject), "code": 1}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def check_jwt_token(
        token: Optional[str] = Header(..., alias='X-Token'),
        raise_err: Optional[str] = Query('1', example='1'),
) -> Union[str, Any]:
    """
    解析验证 headers中为token的值 当然也可以用 Header(..., alias="Authentication") 或者 alias="X-token"
    :param token:
    :param raise_err:
    :return:
    """

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY, algorithms=[ALGORITHM]
        )
        return payload
    except (jwt.JWTError, jwt.ExpiredSignatureError, AttributeError):
        # 抛出自定义异常， 然后捕获统一响应
        if raise_err:
            raise ValueError("access token fail")
        return {
            "sub": '未登录', "code": 0
        }
