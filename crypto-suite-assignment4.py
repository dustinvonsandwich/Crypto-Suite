import base64
import hashlib
import os
import time
import array
from Crypto import Random
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
import Crypto
import binascii


def main():

    key32 = b'\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18'
    key8 = b'\xbf\xc0\xbf\xc0\xbf\xc0\xbf\xc0'


    #encrypt with AES in CBC mode
    time0 = time.time()
    encrypt_file_AES_CBC("bible.txt", key32)
    time1 = time.time()
    print("Elapsed time to encrypt using AES in CBC mode: " + str(time1 - time0) + " Seconds")

    #decrypt with AES in CBC mode
    time2 = time.time()
    decrypt_file_AES_CBC("bible.AES_ENC_CBC", key32)
    time3 = time.time()
    print("Elapsed time to decrypt using AES in CBC mode: " + str(time3 - time2) + " Seconds")

    
    #encrypt with AES in CTR mode
    time4 = time.time()
    encrypt_file_AES_CTR("bible.txt", key32)
    time5 = time.time()
    print("Elapsed time to encrypt using AES in CTR mode: " + str(time5 - time4) + " Seconds")



    #decrypt with AES in CTR mode
    time10 = time.time()
    decrypt_file_AES_CTR("bible.AES_ENC_CTR", key32)
    time11 = time.time()
    print("Elapsed time to decrypt using AES in CTR mode: " + str(time11 - time10) + " Seconds")


    #encrypt with DES in CTR mode
    time6 = time.time()
    encrypt_file_DES_CTR("bible.txt", key8)
    time7 = time.time()
    print("Elapsed time to encrypt using DES in CTR mode: " + str(time7 - time6) + " Seconds")

    #decrypt with DES in CTR mode
    time8 = time.time()
    decrypt_file_DES_CTR("bible.DES_ENC_CTR", key8)
    time9 = time.time()
    print("Elapsed time to decrypt using DES in CTR mode: " + str(time9 - time8) + " Seconds")
    


def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)




def encrypt_file_AES_CBC(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt_AES_CBC(plaintext, key)
    with open("bible.AES_ENC_CBC", 'wb') as fo:
        fo.write(enc)

def encrypt_AES_CBC(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt_file_AES_CBC(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt_AES_CBC(ciphertext, key)
    with open("bible.AES_DEC_CBC", 'wb') as fo:
        fo.write(dec)

def decrypt_AES_CBC(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")


def encrypt_file_AES_CTR(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt_AES_CTR(plaintext, key)
    with open("bible.AES_ENC_CTR", 'wb') as fo:
        fo.write(enc)


def encrypt_AES_CTR(message, key, key_size=256):
    
    iv = b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
    ctr = Crypto.Util.Counter.new(128, initial_value=int(binascii.hexlify(iv), 16))
    
    crypto = AES.new(key, AES.MODE_CTR, counter=ctr)
    encrypted = crypto.encrypt(message)
    return encrypted


def decrypt_file_AES_CTR(file_name, key):
    
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt_AES_CTR(ciphertext, key)
    with open("bible.AES_DEC_CTR", 'wb') as fo:
        fo.write(dec)


def decrypt_AES_CTR(ciphertext, key):
    
    iv = b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
    ctr = Crypto.Util.Counter.new(128, initial_value=int(binascii.hexlify(iv), 16))

    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip(b"\0")


def encrypt_file_DES_CTR(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt_DES_CTR(plaintext, key)
    with open("bible.DES_ENC_CTR", 'wb') as fo:
        fo.write(enc)


def encrypt_DES_CTR(message, key, key_size=256):
    
    nonce = Random.get_random_bytes(4)
    ctr = Counter.new(32, prefix=nonce)
    cipher = DES.new(key, DES.MODE_CTR,counter=ctr)
    encrypted = cipher.encrypt(message)
    return encrypted


def decrypt_file_DES_CTR(file_name, key):
    
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt_DES_CTR(ciphertext, key)
    with open("bible.DES_DEC_CTR", 'wb') as fo:
        fo.write(dec)


def decrypt_DES_CTR(ciphertext, key):
    
    nonce = Random.get_random_bytes(4)
    ctr = Counter.new(32, prefix=nonce)

    cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext




main()
