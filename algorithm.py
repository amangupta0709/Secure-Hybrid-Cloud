import base64
from Crypto import Random
from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher import AES, DES, ARC2

class Encryptor:
    def __init__(self,key,data):
        self.key = key
        self.datalist = [data[:len(data)//3],data[len(data)//3:2*len(data)//3],data[2*len(data)//3:]]

    def aes_encrypt(self,plaintext):
        raw = pad(plaintext,AES.block_size)
        cipher = AES.new(self.key*2, AES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(raw))

    def des_encrypt(self,plaintext):
        raw = pad(plaintext,DES.block_size)
        cipher = DES.new(self.key, DES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(raw))

    def rc2_encrypt(self,plaintext):
        raw = pad(plaintext,ARC2.block_size)
        cipher = ARC2.new(self.key, ARC2.MODE_ECB)
        return base64.b64encode(cipher.encrypt(raw))

    def encrypt(self):
        return self.aes_encrypt(self.datalist[0])+b':'+self.des_encrypt(self.datalist[1])+b':'+self.rc2_encrypt(self.datalist[2])


class Decryptor:
    def __init__(self,key,data):
        self.key = key
        self.datalist = data.split(b':')

    def aes_decrypt(self,ciphertext):
        raw = base64.b64decode(ciphertext)
        cipher = AES.new(self.key*2, AES.MODE_ECB)
        return unpad(cipher.decrypt(raw),AES.block_size)

    def des_decrypt(self,ciphertext):
        raw = base64.b64decode(ciphertext)
        cipher = DES.new(self.key, DES.MODE_ECB)
        return unpad(cipher.decrypt(raw),DES.block_size)

    def rc2_decrypt(self,ciphertext):
        raw = base64.b64decode(ciphertext)
        cipher = ARC2.new(self.key, ARC2.MODE_ECB)
        return unpad(cipher.decrypt(raw),ARC2.block_size)

    def decrypt(self):
        return self.aes_decrypt(self.datalist[0])+self.des_decrypt(self.datalist[1])+self.rc2_decrypt(self.datalist[2])


key = Random.get_random_bytes(8)
print(key)
data = 'here is the algorithm code'.encode()
enc = Encryptor(key,data)
print(enc.encrypt())
dec = Decryptor(key,enc.encrypt())
print(dec.decrypt())

