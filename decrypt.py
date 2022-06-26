import base64, os, hashlib
from Crypto.Util.Padding import pad, unpad 
from Crypto.Cipher import AES


def AESdecrypt(ciphertext, password): 
    key = hashlib.sha256(password.encode()).digest()
    cipher = base64.b64decode(ciphertext) 
    iv = cipher[0:AES.block_size] 
    decipher = AES.new(key, AES.MODE_CBC, iv).decrypt(cipher[AES.block_size:]) 
    return bytes.decode(unpad(decipher, AES.block_size))

with open('encrypted.txt', 'r') as rf:
    rf = rf.read()

password = input("Enter password here: ")
decrypt = AESdecrypt(rf, password)
print(decrypt)
print(rf)