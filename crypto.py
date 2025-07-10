from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_file(input_path, output_path, key):
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))

    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)
