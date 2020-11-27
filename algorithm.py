import base64
import numpy as np, random
from PIL import Image
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


class LSB_Encrypt:

    def __init__(self,src,key):
        self.src = src
        self.key = key

    def random_img(self):
        dX, dY = 512, 512
        xArray = np.linspace(0.0, 1.0, dX).reshape((1, dX, 1))
        yArray = np.linspace(0.0, 1.0, dY).reshape((dY, 1, 1))

        def randColor():
            return np.array([random.random(), random.random(), random.random()]).reshape((1, 1, 3))
        def getX(): return xArray
        def getY(): return yArray
        def safeDivide(a, b):
            return np.divide(a, np.maximum(b, 0.001))

        functions = [(0, randColor),
                    (0, getX),
                    (0, getY),
                    (1, np.sin),
                    (1, np.cos),
                    (2, np.add),
                    (2, np.subtract),
                    (2, np.multiply),
                    (2, safeDivide)]
        depthMin = 2
        depthMax = 10

        def buildImg(depth = 0):
            funcs = [f for f in functions if
                        (f[0] > 0 and depth < depthMax) or
                        (f[0] == 0 and depth >= depthMin)]
            nArgs, func = random.choice(funcs)
            args = [buildImg(depth + 1) for n in range(nArgs)]
            return func(*args)

        img = buildImg()

        # Ensure it has the right dimensions, dX by dY by 3
        img = np.tile(img, (dX / img.shape[0], dY / img.shape[1], 3 / img.shape[2]))

        # Convert to 8-bit, send to PIL and save
        img8Bit = np.uint8(np.rint(img.clip(0.0, 1.0) * 255.0))
        Image.fromarray(img8Bit).save(self.src)

    def Encode(self):

        self.random_img()

        img = Image.open(self.src)
        width, height = img.size
        array = np.array(list(img.getdata()))

        if img.mode == 'RGB':
            n = 3
            m = 0
        # elif img.mode == 'RGBA':
        #     n = 4
        #     m = 1

        total_pixels = array.size//n

        self.key += b":::"
        
        b_key = ''.join([format(i, "08b") for i in self.key])
        req_pixels = len(b_key)

        i=0
        for p in range(total_pixels):
            for q in range(m, n):
                if i < req_pixels:
                    array[p][q] = int(bin(array[p][q])[2:9] + b_key[i], 2)
                    i += 1

        array=array.reshape(height, width, n)
        enc_img = Image.fromarray(array.astype('uint8'), img.mode)
        enc_img.save(self.src)

    def Decode(self):

        img = Image.open(self.src)
        array = np.array(list(img.getdata()))

        if img.mode == 'RGB':
            n = 3
            m = 0

        total_pixels = array.size//n

        hidden_bits = ""
        for p in range(total_pixels):
            for q in range(m, n):
                hidden_bits += (bin(array[p][q])[2:][-1])

        hidden_bits = [hidden_bits[i:i+8] for i in range(0, len(hidden_bits), 8)]

        mykey = b""
        for i in range(len(hidden_bits)):
            if mykey[-3:] == b":::":
                break
            else:
                mykey += chr(int(hidden_bits[i],2)).encode()

        if b":::" in mykey:
            print("Hidden key:", mykey[:-3])


key = base64.b64encode(Random.get_random_bytes(8))[:8]
print(key)
data = 'here is the algorithm code'.encode()
enc = Encryptor(key,data)
print(enc.encrypt())
dec = Decryptor(key,enc.encrypt())
print(dec.decrypt())
img = LSB_Encrypt('output.png',key)
img.Encode()
img.Decode()