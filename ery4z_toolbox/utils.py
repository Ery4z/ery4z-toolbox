import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import os
import string,random


BLOCK_SIZE = 32
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def unpad(s):
    u_s = s[0:-s[-1]]
    return u_s


class AESCipher:

    def __init__(self, KEY='0123456789abcdef0123456789abcdef', IV=Random.new().read(AES.block_size)):
        self.key = hashlib.sha256(KEY.encode()).digest()
        self.iv = IV.zfill(16)
        #self.mode = AES.MODE_ECB
        self.mode = AES.MODE_CBC

    # ----------
    def encrypt(self, raw, base64encode=True):
        cipher = AES.new(self.key, self.mode, self.iv)
        encode = cipher.encrypt(pad(raw).encode("utf-8"))
        if base64encode:
            return base64.b64encode(encode)
        return encode

    def decrypt(self, enc, base64encode=True):
        cipher = AES.new(self.key, self.mode, self.iv)
        if base64encode:
            
            return unpad(cipher.decrypt(base64.b64decode(enc)))

        return unpad(cipher.decrypt(enc))

def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_letters + string.digits
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str
