import os

import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

shared_secret = b'some_shared_secret'
nonce = os.urandom(12)
message = "Test message"

# Encrypt
aesgcm = AESGCM(shared_secret)
encrypted_message = aesgcm.encrypt(nonce, message.encode(), None)

# Decrypt
try:
    decrypted_message = aesgcm.decrypt(nonce, encrypted_message, None)
    print("Decryption successful:", decrypted_message.decode())
except cryptography.exceptions.InvalidTag as e:
    print("Decryption failed:", str(e))
