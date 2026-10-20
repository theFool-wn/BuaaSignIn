# @             Project: BuaaSignIn -> generateRSAkey.py
# @              Author: WangNan
# @       Creation Date: 2026/6/3 21:19
# @         Description: Generate an RSA key pair, one-time
# @ Version Information: Created by WangNan, 2026/6/3
# ===================================================================================

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# 生成私钥（仅后端使用，严禁下发前端）
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
# 私钥PEM字符串，存服务器中
priv_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
# 公钥，下发前端页面
pub_key = private_key.public_key()
pub_pem = pub_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(priv_pem.decode())
print(pub_pem.decode())