import base64, hashlib, os
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

def AESEncrypt(filename, password): 
    key = hashlib.sha256(password.encode()).digest()
 
    iv = os.urandom(AES.block_size) 
 
    padded = pad(filename.encode(), AES.block_size) 
 
    cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
 
    return base64.b64encode(iv + cipher)

with open('file.txt', 'r') as rf:
    rf = rf.read()

password = input("Enter password here: ")
encrypt = AESEncrypt(rf, password)

print(encrypt)

encryption = (''.join(str(encrypt).split('b', 1)))

with open('file.txt', 'w') as wf:
    wf = wf.write(encryption)