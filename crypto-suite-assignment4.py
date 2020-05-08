# A simple interface to pycrypto that accepts a text file as input
# and outputs an encrypted and decrypted version of the text file
# using the specified algorithm. DES and 3DES CTR modes do not
# decrypt properly because they are using random counters instead
# of the same counter used to encrypt. 
# Some IVs used in this interface
# are not random and will render the CBC encryption as insecure. 
# Therefore this tool should be considered for acedemic purposes only
# in its current state.

# Functions come in pairs of encrypt and decryption, one function
# will generate a file for output, while the other will perform the
# actual encryption/decryption. So each algo used here has 4 functions
# to go with it. 


# Author: Dustin Ray
# TCSS 581
# Spring 2020


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


# main function defines keys to use for various algorithms.
# contains calls to encryption and decryption functions, and
# provides runtimes in Seconds for each call.

def main():

    key32 = b'\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18'
    key24 = b'\xbf\xc0\xbf\xc0\xbf\xc0\xbf\xc0\xbf\xc0\xbf\xc0\xbf\xc0\xbf\xc0'
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



    #encrypt with DES in CBC mode
    time6 = time.time()
    encrypt_file_DES_CBC("bible.txt", key8)
    time7 = time.time()
    print("Elapsed time to encrypt using DES in CBC mode: " + str(time7 - time6) + " Seconds")

    #decrypt with DES in CBC mode
    time8 = time.time()
    decrypt_file_DES_CBC("bible.DES_ENC_CBC", key8)
    time9 = time.time()
    print("Elapsed time to decrypt using DES in CBC mode: " + str(time9 - time8) + " Seconds")

    #encrypt with DES3 in CBC mode
    time6 = time.time()
    encrypt_file_DES3_CBC("bible.txt", key24)
    time7 = time.time()
    print("Elapsed time to encrypt using DES3 in CBC mode: " + str(time7 - time6) + " Seconds")

    #decrypt with DES3 in CBC mode
    time8 = time.time()
    decrypt_file_DES3_CBC("bible.DES3_ENC_CBC", key24)
    time9 = time.time()
    print("Elapsed time to decrypt using DES3 in CBC mode: " + str(time9 - time8) + " Seconds")

    #encrypt with DES3 in CTR mode
    time6 = time.time()
    encrypt_file_DES3_CTR("bible.txt", key24)
    time7 = time.time()
    print("Elapsed time to encrypt using DES3 in CTR mode: " + str(time7 - time6) + " Seconds")

    #decrypt with DES3 in CTR mode
    time8 = time.time()
    decrypt_file_DES3_CTR("bible.DES3_ENC_CTR", key24)
    time9 = time.time()
    print("Elapsed time to decrypt using DES3 in CTR mode: " + str(time9 - time8) + " Seconds")
    

# pad function for AES algos. Brings block size to required block size
# by AES.
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


def encrypt_file_DES_CBC(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt_DES_CBC(plaintext, key)
    with open("bible.DES_ENC_CBC", 'wb') as fo:
        fo.write(enc)

def encrypt_DES_CBC(message, key, key_size=256):
    
    message = pad(message)
    iv = Random.new().read(DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt_file_DES_CBC(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt_DES_CBC(ciphertext, key)
    with open("bible.DES_DEC_CBC", 'wb') as fo:
        fo.write(dec)

def decrypt_DES_CBC(ciphertext, key):
    iv = ciphertext[:DES.block_size]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[DES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file_DES3_CBC(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt_DES3_CBC(plaintext, key)
    with open("bible.DES3_ENC_CBC", 'wb') as fo:
        fo.write(enc)

def encrypt_DES3_CBC(message, key):
    
    message = pad(message)
    iv = Random.new().read(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt_file_DES3_CBC(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt_DES3_CBC(ciphertext, key)
    with open("bible.DES3_DEC_CBC", 'wb') as fo:
        fo.write(dec)

def decrypt_DES3_CBC(ciphertext, key):
    iv = ciphertext[:DES3.block_size]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[DES3.block_size:])
    return plaintext.rstrip(b"\0")



def encrypt_file_DES3_CTR(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt_DES3_CTR(plaintext, key)
    with open("bible.DES3_ENC_CTR", 'wb') as fo:
        fo.write(enc)


def encrypt_DES3_CTR(message, key):
    
    nonce = Random.get_random_bytes(4)
    ctr = Counter.new(32, prefix=nonce)
    cipher = DES3.new(key, DES3.MODE_CTR,counter=ctr)
    encrypted = cipher.encrypt(message)
    return encrypted


def decrypt_file_DES3_CTR(file_name, key):
    
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt_DES3_CTR(ciphertext, key)
    with open("bible.DES3_DEC_CTR", 'wb') as fo:
        fo.write(dec)


def decrypt_DES3_CTR(ciphertext, key):
    
    nonce = Random.get_random_bytes(4)
    ctr = Counter.new(32, prefix=nonce)

    cipher = DES3.new(key, DES3.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext
    


main()
