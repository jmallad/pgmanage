import os, base64, hashlib, random
# Authenticated symmetric encryption tool
from cryptography.fernet import Fernet

def encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv+ct).decode()


def decrypt(encrypted_text, key):
    data = base64.b64decode(encrypted_text.encode())
    iv = data[:16]
    encrypted_key = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    conn_pass = decryptor.update(encrypted_key) + decryptor.finalize()

    return conn_pass.decode()

# Password hashing constants
SALT_LENGTH = 16
HASH_ALG = 'sha256'
PBKDF2_ITERS = 15000

def make_hash(plaintext):
    # Generate random salt [https://cryptography.io/en/latest/random-numbers/]
    salt = os.urandom(SALT_LENGTH)
    # Create authenticated hash
    passhash = hashlib.pbkdf2_hmac(HASH_ALG,
                                   bytes(plaintext, encoding='utf-8'),
                                   salt,
                                   PBKDF2_ITERS)
    # Return base64-encoded result as a string
    return base64.b64encode(passhash).decode()


                                   
