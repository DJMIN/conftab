import base64
import html
import typing
import logging
import os

import Crypto.Signature.PKCS1_v1_5 as sign_PKCS1_v1_5  # 用于签名/验签

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5  # 用于加密
from Crypto import Random
from Crypto.Hash import SHA256

logger = logging.getLogger('ras')

"""
PKCS#1、PKCS#5、PKCS#7区别
PKCS5：PKCS5是8字节填充的，即填充一定数量的内容，使得成为8的整数倍，而填充的内容取决于需要填充的数目。例如，串0x56在经过PKCS5填充之后会成为0x56 0x07 0x07 0x07 0x07 0x07 0x07 0x07因为需要填充7字节，因此填充的内容就是7。当然特殊情况下，如果已经满足了8的整倍数，按照PKCS5的规则，仍然需要在尾部填充8个字节，并且内容是0x08,目的是为了加解密时统一处理填充。
PKCS7：PKCS7与PKCS5的区别在于PKCS5只填充到8字节，而PKCS7可以在1-255之间任意填充。
PKCS1：在进行RSA运算时需要将源数据D转化为Encryption block（EB）。其中pkcs1padding V1.5的填充模式按照以下方式进行
(1) EB = 00+BT+PS+00+D
EB：为填充后的16进制加密数据块，长度为1024/8 = 128字节（密钥长度1024位的情况下）
00：开头为00，是一个保留位
BT：用一个字节表示，在目前的版本上，有三个值00、01、02，如果使用公钥操作，BT为02，如果用私钥操作则可能为00或01
PS：填充位，PS = k － 3 － D 个字节，k表示密钥的字节长度，如果我们用1024bit的RSA密钥，k=1024/8=128字节，D表示明文数据D的字节长度，如果BT为00，则PS全部为00，如果BT为01，则PS全部为FF，如果BT为02，PS为随机产生的非0x00的字节数据。
00：在源数据D前一个字节用00表示
D：实际源数据
公式(1)整个EB的长度等于密钥的长度。
注意：对于BT为00的，数据D中的数据就不能以00字节开头，要不然会有歧义，因为这时候你PS填充的也是00，就分不清哪些是填充数据哪些是明文数据了，但如果你的明文数据就是以00字节开头怎么办呢？对于私钥操作，你可以把BT的值设为01，这时PS填充的FF，那么用00字节就可以区分填充数据和明文数据，对于公钥操作，填充的都是非00字节，也能够用00字节区分开。如果你使用私钥加密，建议你BT使用01，保证了安全性。
对于BT为02和01的，要保证PS至少要有八个字节长度
因为EB = 00+BT+PS+00+D = k
所以D <= k － 3 － 8，所以当我们使用128字节密钥对数据进行加密时，明文数据的长度不能超过128 － 11 = 117字节
当RSA要加密数据大于(k－11)字节时怎么办呢？把明文数据按照D的最大长度分块，然后逐块加密，最后把密文拼起来就行。
"""


class RSACtrl:
    def __init__(
            self,
            private_key=None, public_key=None,
            privatekey_path=None, publickey_path=None
    ):
        # 实现RSA 非对称加解密
        self.private_key = private_key  # 私钥
        self.public_key = public_key  # 公钥

        self.pri_obj = None  # 私钥obj
        self.pub_obj = None  # 公钥obj
        self.cert = None  # 证书

        self.private_key_max_handle_msg_len = 0
        self.public_key_max_handle_msg_len = 0

        self.load_key()

        self.privatekey_path = privatekey_path  # 私钥
        self.publickey_path = publickey_path  # 公钥

    def __str__(self):
        return f'[{"私钥" if self.private_key else "无"}|{"公钥" if self.public_key else "无"}] {str(self.private_key)[:50]} {str(self.public_key)[:50]}'

    def __repr__(self):
        return f'[{"私钥" if self.private_key else "无"}|{"公钥" if self.public_key else "无"}] {str(self.private_key)} {str(self.public_key)}'

    def load_public_key(self, publickey):
        if isinstance(publickey, str):
            publickey = publickey.encode()
        self.public_key = publickey
        self.pub_obj = PKCS1_v1_5.new(RSA.importKey(self.public_key))
        self.public_key_max_handle_msg_len = getattr(self.pub_obj, '_key').size_in_bytes() - 11
        return publickey

    def load_private_key(self, private_key, auto_public=True):
        if isinstance(private_key, str):
            private_key = private_key.encode()
        pri_obj = RSA.importKey(private_key)
        self.cert = pri_obj.export_key("DER")  # 生成证书 -- 它和私钥是唯一对应的
        self.private_key = pri_obj.export_key()
        self.pri_obj = PKCS1_v1_5.new(pri_obj)
        # self.pri_obj = PKCS1_v1_5.new(pri_obj)
        self.private_key_max_handle_msg_len = getattr(self.pri_obj, '_key').size_in_bytes()
        if auto_public:
            # 通过私钥生成公钥  (公钥不会变 -- 用于只知道私钥的情况)
            self.load_public_key(pri_obj.publickey().export_key())

        return pri_obj

    def load_key(self):
        if self.private_key:
            self.load_private_key(self.private_key)
        if self.public_key:
            self.load_public_key(self.public_key)

    @staticmethod
    def get_data_form_file(path):
        with open(path, 'rb') as x:
            return x.read()

    def load_public_key_from_file(self, path=None):
        publickey = self.get_data_form_file(path)
        self.publickey_path = path
        self.load_public_key(publickey)
        return publickey

    def load_private_key_obj_from_file(self, path=None, auto_public=True):
        # 从文件导入密钥
        private_key = self.get_data_form_file(path)
        self.privatekey_path = path
        return self.load_private_key(private_key, auto_public)

    def load_key_file(self):
        if self.publickey_path:
            publickey = self.load_public_key_from_file(self.publickey_path)
        else:
            publickey = None
        if self.privatekey_path:
            self.load_private_key_obj_from_file(self.privatekey_path, auto_public=not bool(self.publickey_path))
        if self.publickey_path and publickey != self.public_key:
            raise ValueError(f'公钥文件【{self.publickey_path}】和私钥文件【{self.privatekey_path}】不匹配')
        return self

    def save_key_file(self):
        # 写入文件
        with open(self.privatekey_path, "wb") as x:
            x.write(self.private_key)
        with open(self.publickey_path, "wb") as x:
            x.write(self.public_key)
        return self

    @staticmethod
    def generate_key(bit=2048):
        # 手动生成一个密钥对(项目中的密钥对一般由开发来生成)，生成密钥对的时候，可以指定生成的长度，一般推荐使用1024bit，
        # 1024bit的rsa公钥，最多只能加密117byte的数据，数据流超过这个数则需要对数据分段加密，
        # 目前1024bit长度的密钥已经被证明了不够安全，尽量使用2048bit长度的密钥，
        # 2048bit长度密钥最多能加密245byte长度的数据计算长度公式：密钥长度 / 8 - 11 = 最大加密量(单位bytes)下面生成一对2048bit的密钥：
        # x = RSA.generate(2048)
        x = RSA.generate(bit, Random.new().read)  # 也可以使用伪随机数来辅助生成
        privatekey = x.export_key()  # 私钥
        publickey = x.publickey().export_key()  # 公钥
        logger.debug(f"生成公私钥对：{type(privatekey)} {privatekey} {type(publickey)} {publickey}")
        return privatekey, publickey

    def generate_key_and_load(self, bit=2048):
        self.private_key, self.public_key = self.generate_key(bit)
        self.load_private_key(self.private_key)
        return self

    def generate_key_and_load_and_save_file(self, bit=2048):
        """
        2048位RSA密钥生成需要2秒，4096需要15秒
        """
        self.generate_key_and_load(bit)
        self.save_key_file()
        return self

    def load_key_file_or_generate_key_and_load_and_save_file(self, bit=2048):
        if self.publickey_path or self.privatekey_path:
            try:
                self.load_key_file()
            except FileNotFoundError:
                if self.privatekey_path:
                    self.generate_key_and_load_and_save_file(bit)
                else:
                    raise ValueError('如要生成密钥对，必须给出私钥文件保存路径，目前公钥路径 "{}" 未找到文件，私钥路径为 {}'.format(
                        os.path.realpath(self.publickey_path), self.privatekey_path
                    ))
        else:
            raise ValueError('必须给出密钥文件保存路径，目前公私密钥路径均为空')
        return self

    def load_or_generate_key(self, bit=2048):
        if self.publickey_path or self.privatekey_path:
            self.load_key_file_or_generate_key_and_load_and_save_file(bit)
        elif self.public_key or self.private_key:
            self.load_key()
        else:
            self.generate_key_and_load()
        return self

    """
    ① 使用公钥 - 私钥对信息进行"加密" + “解密”
    作用：对信息进行公钥加密，私钥解密。 应用场景：
    A想要加密传输一份数据给B，担心使用对称加密算法易被他人破解（密钥只有一份，
    一旦泄露，则数据泄露），故使用非对称加密。
    信息接收方可以生成自己的秘钥对，即公私钥各一个，然后将公钥发给他人，
    私钥自己保留。

    A使用公钥加密数据，然后将加密后的密文发送给B，B再使用自己的私钥进行解密，
    这样即使A的公钥和密文均被第三方得到，
    第三方也要知晓私钥和加密算法才能解密密文，大大降低数据泄露风险。
    """

    def encrypt_with_rsa(self, plain_text):
        # 先公钥加密
        secret_byte_obj = self.pub_obj.encrypt(plain_text.encode())
        return secret_byte_obj

    def decrypt_with_rsa(self, secret_byte_obj):
        if isinstance(secret_byte_obj, str):
            secret_byte_obj = secret_byte_obj.encode()
        # 后私钥解密
        _byte_obj = self.pri_obj.decrypt(secret_byte_obj, Random.new().read)
        plain_text = _byte_obj.decode()
        return plain_text

    def encrypt_with_rsa_split_base64(self, msg, b64=True) -> str:
        """
        公钥加密
        str分段后 加密 join base64编码 返回str
        """
        if not self.public_key:
            raise ValueError(f'【失败】公钥加密，公钥为: {self.public_key}')
        # 分段加密
        encrypt_text = []
        if isinstance(msg, (int, dict)):
            msg = str(msg)
        if isinstance(msg, str):
            msg = msg.encode("utf-8")
        # 对数据进行分段加密
        for i in range(0, len(msg), self.public_key_max_handle_msg_len):
            cont = msg[i:i + self.public_key_max_handle_msg_len]
            encrypt_text.append(self.pub_obj.encrypt(cont))
        # 分段加密完进行拼接
        cipher_text = b''.join(encrypt_text)
        if b64:
            # base64进行编码
            cipher_text = base64.b64encode(cipher_text)
        return cipher_text.decode()

    def decrypt_with_rsa_split_base64(self, secret_byte_obj, encoding='utf-8', b64=True) -> str:
        """
        私钥解密
        str base64解码 分段解密 join 返回str
       """
        if not self.private_key:
            raise ValueError(f'【失败】私钥解密，私钥为: {self.private_key}')
        if isinstance(secret_byte_obj, str):
            secret_byte_obj = secret_byte_obj.encode()
        if b64:
            secret_byte_obj = base64.b64decode(secret_byte_obj)

        # 分段加密
        encrypt_bytes = []
        msg_len = self.private_key_max_handle_msg_len
        # 对数据进行分段加密
        for i in range(0, len(secret_byte_obj), msg_len):
            cont = secret_byte_obj[i:i + msg_len]
            # 后私钥解密
            _byte_obj = self.pri_obj.decrypt(cont, Random.new().read)

            encrypt_bytes.append(_byte_obj)
        # 分段加密完进行拼接
        encrypt_byte = b''.join(encrypt_bytes)
        try:
            plain_text = encrypt_byte.decode(encoding)
        except Exception as ex:
            logger.warning(f'私钥解密 [ERROR] {ex}: {encoding.__repr__()}')
            plain_text = encrypt_byte.decode(encoding, errors='xmlcharrefreplace')
            plain_text = html.unescape(plain_text)
        return plain_text

    def to_sign_with_private_key(self, msg: typing.Union[str, bytes], b64=True) -> str:
        """
        私钥签名
        """
        if not self.private_key:
            raise ValueError(f'【失败】私钥签名，私钥为: {self.private_key}')
        signer_pri_obj = sign_PKCS1_v1_5.new(RSA.importKey(self.private_key))
        rand_hash = SHA256.new()
        if isinstance(msg, str):
            msg = msg.encode()
        rand_hash.update(msg)
        signature = signer_pri_obj.sign(rand_hash)
        if b64:
            signature = base64.b64encode(signature)
        return signature.decode()

    def to_verify_with_public_key(
            self, msg: typing.Union[str, bytes], signature: typing.Union[str, bytes], b64=True) -> bool:
        """
        公钥验签
        """
        if not self.public_key:
            raise ValueError(f'【失败】公钥验签，公钥为: {self.public_key}')
        verifier = sign_PKCS1_v1_5.new(RSA.importKey(self.public_key))
        _rand_hash = SHA256.new()
        if isinstance(msg, str):
            msg = msg.encode()
        _rand_hash.update(msg)
        try:
            if isinstance(signature, str):
                signature = signature.encode()
            if b64:
                signature = base64.b64decode(signature)
            verifier.verify(_rand_hash, signature)
            verify = True
        except ValueError as ex:
            if str(ex) == 'Invalid signature':
                verify = False
            else:
                raise ex
        return verify  # true / false

    def encode(self, msg: typing.Union[str, bytes], b64=True) -> str:
        """
        公钥加密
         str分段后 加密 join base64编码 返回str
        """
        return self.encrypt_with_rsa_split_base64(msg, b64=b64)

    def decode(self, secret: typing.Union[str, bytes], encoding='utf-8', b64=True) -> str:
        """
        私钥解密
         str base64解码 分段解密 join 返回str
        """
        return self.decrypt_with_rsa_split_base64(secret, encoding=encoding, b64=b64)

    def sign(self, msg: typing.Union[str, bytes], b64=True) -> str:
        """
        私钥签名
        """
        return self.to_sign_with_private_key(msg, b64=b64)

    def verify(self, msg: typing.Union[str, bytes], signature: typing.Union[str, bytes], b64=True) -> bool:
        """
        公钥验签
        """
        return self.to_verify_with_public_key(msg, signature, b64=b64)

    def check(self):
        """
        检测类函数方法以及公私密钥对可用性
        """
        print(self)
        self.verifier_with_signature(print)
        self.verifier_without_signature(print)

    def verifier_without_signature(self, logger_info: typing.Callable = logging.info):
        # 加解密验证
        text = "I love CA!"
        assert text == self.decrypt_with_rsa(self.encrypt_with_rsa(text))
        logger_info("rsa 加/解密验证 success！")

    def verifier_with_signature(self, logger_info: typing.Callable = logging.info):
        # 签名/验签
        text = "I love CA!"
        assert self.to_verify_with_public_key(text, self.to_sign_with_private_key(text))
        logger_info("rsa 签名/验签 success!")


def encode_and_sign(rsa_receiver_with_pub, rsa_sender_with_pri, data):
    """接收端公钥加密 并用 发送端私钥签名 再===连接 接收端公钥加密"""
    secret = rsa_receiver_with_pub.encode(data)
    signature = rsa_sender_with_pri.sign(secret)
    return rsa_receiver_with_pub.encode(f'{secret}==={signature}')


def verify_and_decode(rsa_sender_with_pub, rsa_receiver_with_pri, secret):
    """接收端私钥解密 并===切分密文和数字签名 发送端公钥验证签名 通过 则接收端私钥解密 否则 抛异常"""
    secret = rsa_receiver_with_pri.decode(secret)
    secret, signature = secret.rsplit('===', maxsplit=1)
    is_secret_no_mid_attack = rsa_sender_with_pub.verify(secret, signature)
    if is_secret_no_mid_attack:
        return rsa_receiver_with_pri.decode(secret)
    else:
        raise ValueError('警告！！！数字证书签名验证不通过，数据正文被中间人攻击并篡改')


if __name__ == '__main__':
    # __data = ''.join(str(i)+' ' for i in range(10000))
    __data = """
    ① 使用 公钥 - 私钥 对 信息进行 "加密" + “解密”
    作用：对信息进行公钥加密，私钥解密。 应用场景：
    A想要加密传输一份数据给B，担心使用对称加密算法易被他人破解（密钥只有一份，
    一旦泄露，则数据泄露），故使用非对称加密。
    信息接收方可以生成自己的秘钥对，即公私钥各一个，然后将公钥发给他人，
    私钥自己保留。

    A使用公钥加密数据，然后将加密后的密文发送给B，B再使用自己的私钥进行解密，
    这样即使A的公钥和密文均被第三方得到，
    第三方也要知晓私钥和加密算法才能解密密文，大大降低数据泄露风险。
    
    ② 使用 私钥 - 公钥 对 信息进行 "签名" + “验签”
    
    作用：对解密后的文件的完整性、真实性进行验证（繁琐但更加保险的做法，很少用到）
    应用场景： A有一私密文件欲加密后发送给B，又担心因各种原因导致B收到并解密后的文件并非完整、真实的原文件（可能被篡改或丢失一部分），所以A在发送前对原文件进行签名，将[签名和密文]一同发送给B让B收到后用做一下文件的 [解密 + 验签],
    均通过后-方可证明收到的原文件的真实性、完整性。
    
    如果是加密的同时又要签名，这个时候稍微有点复杂。
    1、发送者和接收者需要各持有一对公私钥，也就是4个钥匙。
    2、接收者的公私钥用于机密信息的加解密
    3、发送者的公私钥用于机密信息的签名/验签
    4、接收者和发送者都要提前将各自的[公钥]告知对方。
    """
    __rsa_ctrl1_pri = RSACtrl(privatekey_path='pri1.pem').load_or_generate_key(1024)
    __rsa_ctrl1_pub = RSACtrl(publickey_path='pub1.pem').load_or_generate_key(1024)
    __rsa_ctrl2_pri = RSACtrl(privatekey_path='pri2.pem').load_or_generate_key(1024)
    __rsa_ctrl2_pub = RSACtrl(publickey_path='pub2.pem').load_or_generate_key(1024)

    __rsa_ctrl1 = RSACtrl(privatekey_path='pri1.pem', publickey_path='pub1.pem').load_or_generate_key(1024)
    __rsa_ctrl2 = RSACtrl(privatekey_path='pri2.pem', publickey_path='pub2.pem').load_or_generate_key(1024)
    __rsa_ctrl1.check()
    __rsa_ctrl2.check()

    __rsa_ctrl3 = RSACtrl(
        private_key='-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAse1EX0Gs5le1VNG3GkmE1jMRXgjg3vCKF5paKs0EjlNh/7og\nw0xSqdYXXU3zks3+8Up56YzMBjVru7kYwal69C0ikWCrxJEpE/OtlFze0iv+cwhH\nrHQGirgm0FTu2IHa5zhy1TzhrXeyoojw8r2uFEC7aj0yXH021IVeOFuhpyofh5fU\nRPbXkxRypjyupbdksZbHzNSoWAjnsqytGtL9fmflq0zxddADG7Xy3DVEqd9W+dYY\nIZTckd8y1rWli0kGKrjwhkvSqXeyKvRCukx4DML2T5d6gMmYRNoXq40Wqtey4Hp0\nFLJXSSWRvYB4V5PE54KJagnYjVs7bWY6/wQtsQIDAQABAoIBAAFR6HphLilfjFMk\nsuQ7WESfSH1DSTlILSsViF6VyqdMZa9ILATs4pZbVe0pllFwDSiQuBCwLGWNpQbl\njbImmeiYst9jmWSd+9E3wyF1EqtaG5MyhBcavX9vFC0imyrApF1HozzzHJy9BQaN\nB+YSG4nvjMBiE7cBUAxBsMgv4FYxT/FRAupSUCDE6i0YgF07ryJAd2zQJsW/nj2P\nJXdWV3Y0VeAn6QarXmswXv9B3OO7cc6gkrm9vCzdeosJyA5AeQK/00In5XDrsawM\nyWVsX7Rag8xfYQZ7uB3KZFnuBi5gwnD8rC1Pyyd7Vqwx4FFLo0HGjQMeSDFYb01V\nqqJTQsECgYEAxWLmw5QrXTY8Eo571WDIYB1MD/KbpnySl7Cc5Dx56PkZmbRHxvFZ\nypvJgXaRWGH7f0A5TpubO+09QoIahABNkmhuojkGVcZH0i40Xfw80r+aX5JmFTl7\nX41wOTYTc9m8MGr4rk2lA7gxgDGjLP/uE7TaOM/CYsS8XopgjQyzUcECgYEA5sMT\nFADwoEN7kUlR1Z/eeAZ3cn9SAYxGTc77AXKr/D4Q0DLDpZ8TJpmBhaJmAmlY4TKu\nqyW0Kt/ajs/YIMS5CPNg2DN0fzBSFaHgVl2geitghSi2XonzCzKvyr3PJCsUTIXV\n7vzwlPF6yHAHzm19UWmE+8XLbSkCkMpsNTUT9/ECgYEApyjbvvPjSXwdoaVy78CX\n0PXerX7LHFJRHw9dvtgMciVK7eVECBHq9e+61d3gtxW7lAeCwLR84WJHR+TAqdtL\n1lqEnvNmDwvtVOz2QkXUCLJk/N0RgJX+imxQhtLp5GmXuvVMhuiQf7bkjOj8hKZ1\nK9E0IXqo51YvJG1R2QHRdsECgYB3sxrTVoV67GZNf7XWVP4mTlxpZQfZy7SwKbxk\nDOKPjnZUOPDpmXFqpVfdRNcbSyASeKLIHl+tmb6aM9ANd13v+abznwU/8IWzuOtQ\ngXJ7zMJdcDfhJDeRSHKNfRXU0g/OfeHx/Pyilfw1un8iIgNOVqjnnLsf3ZT6HDYz\nB1xbUQKBgHJHZ9Y4ifQ4Qqpk6lvhE//kOIzR9cVYlJ1HAX/3xoQQ/yPgg6M2RiyE\nBYJXaSXanAU1X0qXQFFsG3dYKvqjVTNylWVupSmFVKh1AAjHG+Hj8c6QIr6nZ8KQ\n79Xg+rvjW9VLuIRa9h7W3yVouZLzN+NpoMm3Rd1KCh4RWJy9hw9P\n-----END RSA PRIVATE KEY-----',
        public_key='-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAse1EX0Gs5le1VNG3GkmE\n1jMRXgjg3vCKF5paKs0EjlNh/7ogw0xSqdYXXU3zks3+8Up56YzMBjVru7kYwal6\n9C0ikWCrxJEpE/OtlFze0iv+cwhHrHQGirgm0FTu2IHa5zhy1TzhrXeyoojw8r2u\nFEC7aj0yXH021IVeOFuhpyofh5fURPbXkxRypjyupbdksZbHzNSoWAjnsqytGtL9\nfmflq0zxddADG7Xy3DVEqd9W+dYYIZTckd8y1rWli0kGKrjwhkvSqXeyKvRCukx4\nDML2T5d6gMmYRNoXq40Wqtey4Hp0FLJXSSWRvYB4V5PE54KJagnYjVs7bWY6/wQt\nsQIDAQAB\n-----END PUBLIC KEY-----'
    ).load_or_generate_key()
    __rsa_ctrl4 = RSACtrl(
        private_key='-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAwwINavnVgkwfCdsPb/VbSwfF2fll7CVPlmygK9TvfFpyroU7\nOVbCbpT5pRVpGKPMk9J1Idt9rhsdhQH6tMIObyRbaZb6nV8O7sHy2F6uM/wZ4+SJ\nbCRepMWjCbzvVj8/V1kjpLPxMGz1TVUur7Wo4jTBv8dxgnoV5UOH2cnk35Q86iAW\nXFb8BhRHU3lIWgfNPhp+nVkKcpj+Db11SLN5M//9XKlhoPLOGti3xq7Tkahe0bWu\n3hErTGCIGPjh0gczpTUlJh9CdHub+nuDVWub1YQHAswOj/Hra1A59Gk2t8hbB4V5\nBRmUEcBMjpwA8nsNw1B2YcGPFxjhuxUf8pEVcwIDAQABAoIBAB/ddP3XBzl8YNIG\ndrZPvHQ9N+pPY4U7745f/6hJ6jxCt1ynLq9G6wyQ0V5Vak/5bBN3n2ZB7H6HtcIn\nOaVR1HP61+kgH6GZh+Ih1SHgDs0107E2hfIi20hHd0W/FsjcGuiWC0n9kVrdYxQY\n6EEUCR21izdgSr8MXgmRiGBhKkISOPq9xwZlx8ksVXghtdY6afVRJZKpTrwwagc8\nrG28bYoB1/W4yZZ0ile/9VQ3OGa7BgkjGo5Hz68Ie8lJ+MQSNDXUjGYznbH+XWaY\nHoy3R/5uusOPjHyozAVEuTab0BB8RvVMMOkeXxZiD9WykpV7S2ji7pWdKdkW4Rs+\nO1hzZXECgYEA2d2SSsZ5blvq5eBdfIMK0OQc8lPrqEkkkhBCpL7U4o/kJgD6xr6u\nubQWjA56cQPowOYongYfZQdfLVNyRrbX2mUf7ChGkxdwH8ZGfbJRpwGzG5wAf9/L\nf9GnnAOxn4KRckAZiN51DddOPTSIqwrI4HUax3fdKDxPuuYo871MSvkCgYEA5SQ/\n6v4YsLXxqpaUWb36O3GO8Q0wcJa4tq2Yj4G+w56+rwpjAnV+mrGGyd8oJ5rWnoOP\ndrGv/Qo39Uy9LhLqHNdcPUCvTsWtGSp9PGhe251Fba1zg37Z1gAZJpkUkMUv2L+y\nW4ydfcWR31sqWXczjdqeyGhI3S3QlN01pJoVMssCgYBnKq8tzZKPGeO/+2EJpxwm\nEv9KGUdMp2Yz7JNCZEN3DeBhxrD6EC25LnhG1kxQ3CMJxXOScR/IvZbqZcuFhOvu\nNVjKgb/5w22K/l8/AoP766ge+N6bryQ0YNlX3b/s4u1xBr2QvJb9eOlJvmjBZhf9\ngjauIiqN9RFkVb0qvoc0MQKBgQCCBBmIevkDe5lOU/aFHTiY9gxHVlZ/6+WPMdz4\nwIO/d5l2tIwNXyGhIM38SXT9U+wnMTr7/EKBb4Tk2NAXDoBsMP6Tetp99cgMGYHJ\n/uaj8g7s9pguqpFrzc53ijCTHG/TqqHHNHhAXxQwCghzjyFfggbKa/G8HjzV2taP\nOSaCFQKBgQCetkMdwpR6CF+NBa2ztJ1mQfLb2R80TDxMxVQNlNFZjtzZLN48SFiO\nQOKl0ZZcmcZab0HWt/0n0N5AlU4BHD+pqbvLSY51bPkD/b3AVC3xRbs4+2n5hQ15\no7q92+YB9dD09e8FHxaRKgKCFC1cVaeCM9aItVfCVWTljCtrOq3c2Q==\n-----END RSA PRIVATE KEY-----',
        public_key='-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwwINavnVgkwfCdsPb/Vb\nSwfF2fll7CVPlmygK9TvfFpyroU7OVbCbpT5pRVpGKPMk9J1Idt9rhsdhQH6tMIO\nbyRbaZb6nV8O7sHy2F6uM/wZ4+SJbCRepMWjCbzvVj8/V1kjpLPxMGz1TVUur7Wo\n4jTBv8dxgnoV5UOH2cnk35Q86iAWXFb8BhRHU3lIWgfNPhp+nVkKcpj+Db11SLN5\nM//9XKlhoPLOGti3xq7Tkahe0bWu3hErTGCIGPjh0gczpTUlJh9CdHub+nuDVWub\n1YQHAswOj/Hra1A59Gk2t8hbB4V5BRmUEcBMjpwA8nsNw1B2YcGPFxjhuxUf8pEV\ncwIDAQAB\n-----END PUBLIC KEY-----'
    ).load_or_generate_key()
    __rsa_ctrl3.check()
    __rsa_ctrl4.check()

    __rsa_ctrl5 = RSACtrl().load_or_generate_key()
    __rsa_ctrl5.check()

    __mi_wen = __rsa_ctrl1.encode(__data)
    print(__mi_wen)

    __ming_wen = __rsa_ctrl1.decode(__mi_wen)
    print(__ming_wen)

    __signature = __rsa_ctrl2.sign(__mi_wen)
    print(__signature)

    __is_ming_wen = __rsa_ctrl2.verify(__ming_wen, __signature)
    print(__is_ming_wen)

    __mi_wen_and_signature = encode_and_sign(__rsa_ctrl1_pub, __rsa_ctrl2_pri, __data)
    __ming_wen = verify_and_decode(__rsa_ctrl2_pub, __rsa_ctrl1_pri, __mi_wen_and_signature)
    print(__ming_wen)
