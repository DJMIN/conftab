# coding=utf-8
import typing
from Crypto.Cipher import DES3  # 加密解密方法
import base64

BS = DES3.block_size


def pad(s):
    if isinstance(s, str):
        return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    elif isinstance(s, bytes):
        return s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()
# 定义 padding 即 填充 为PKCS7

def un_pad(s):
    return s[0:-s[-1]]


class DES3Ctrl(object):
    def __init__(self, key, iv=b'conftab*'):
        if len(key) < 24:
            key += '*' * (24 - len(key))
        elif len(key) > 24:
            key = key[:24]
        if len(iv) < 8:
            iv += '*' * (8 - len(iv))
        elif len(iv) > 8:
            iv = iv[:8]
        self.key = key
        self.iv = iv  # IV偏移量
        self.mode = DES3.MODE_CBC

    # DES3的加密模式为CBC
    def encrypt(self, text: typing.Union[str, bytes]):
        text = pad(text)
        cryptor = DES3.new(self.key, self.mode, self.iv)
        # print(text)
        if isinstance(text, str):
            text = text.encode()

        x = len(text) % 8
        if x != 0:
            text = text + b'\0' * (8 - x)  # 不满16，32，64位补0
        ciphertext = cryptor.encrypt(text)
        return base64.standard_b64encode(ciphertext).decode("utf-8")

    def decrypt(self, text: typing.Union[str], encoding="utf-8"):
        cryptor = DES3.new(self.key, self.mode, self.iv)
        de_text = base64.standard_b64decode(text)
        plain_text = cryptor.decrypt(de_text).rstrip(b'\0')
        plain_text = un_pad(plain_text)
        if encoding:
            plain_text = str(plain_text.decode(encoding=encoding))
        return plain_text


if __name__ == '__main__':
    MYKEY = "abcdefgh12345678ABCDEFGH"  # 三组八字节密匙，即24字节
    IV = b"aaaabb111bb"  # CBC模式的初始化向量，8字节
    pc = DES3Ctrl(MYKEY, IV)
    message = '''\n'''.join(str(i) for i in range(10000))
    message = '''1''' * 10000
    print(len(message))
    e = pc.encrypt(message)  # 加密内容
    d = pc.decrypt(e)  # 解密内容
    # print(d)
    print(len(d))
