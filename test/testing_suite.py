# Assume diffie_hellman_utils.py is properly implemented and imported
import os

import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from user_module.user import User
from diffiehellman_utils import DiffieHellmanUtils

# Hardcoded values for testing
shared_secret = b'some_shared_secret'
nonce = os.urandom(12)  # Generate once, use this for both encryption and decryption in test
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
