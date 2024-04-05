#!/usr/bin/env python
# coding: utf-8

import base64
import os
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class DiffieHellmanUtils:
    def __init__(self):
        pass

    def is_prime(self, number):
        """Check if a number is prime."""
        if number <= 1:
            return False
        if number <= 3:
            return True
        if number % 2 == 0 or number % 3 == 0:
            return False
        i = 5
        while i * i <= number:
            if number % i == 0 or number % (i + 2) == 0:
                return False
            i += 6
        return True

    def is_primitive_root(self, number, prime_num):
        """Check if a number is a primitive root modulo a given prime."""
        if not self.is_prime(prime_num):
            return False
        if number < 1 or number >= prime_num:
            return False
        factors = set()
        phi = prime_num - 1
        n = phi
        i = 2
        while i * i <= n:
            while n % i == 0:
                factors.add(i)
                n //= i
            i += 1
        if n > 1:
            factors.add(n)
        for factor in factors:
            if pow(number, phi // factor, prime_num) == 1:
                return False
        return True

    def find_primitive_root(self, prime_number):
        """Find a primitive root for a given prime number."""
        if prime_number == 2:
            return 1
        phi = prime_number - 1
        factors = self.find_factors(phi)
        for number in range(2, prime_number):
            if all(pow(number, phi // factor, prime_number) != 1 for factor in factors):
                return number
        return None

    def find_factors(self, number):
        """Find all prime factors of a given number."""
        factors = set()
        i = 2
        while i * i <= number:
            if number % i == 0:
                factors.add(i)
                number //= i
            else:
                i += 1
        if number > 1:
            factors.add(number)
        return factors

    def generate_prime(self, min_value=0, max_value=400):
        """Generate a prime number within a specified range."""
        while True:
            number = random.randint(min_value, max_value)
            if self.is_prime(number):
                return number

    def calculate_public_key(self, prime, generator, private_key):
        """Calculate a public key given a prime, generator, and private key."""
        public_key = pow(generator, private_key, prime)
        return public_key

    def calculate_shared_secret(self, prime, private_key, other_public_key, salt=None):
        """Calculate the shared secret using Diffie-Hellman key exchange."""
        shared_secret_int = pow(other_public_key, private_key, prime)
        shared_secret = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, byteorder='big')
        derived_key = self.derive_key(shared_secret, salt, 32)
        return derived_key

    def calculate_shared_secret_base64(self, prime, other_public_key, private_key, salt=None):
        """Calculate the shared secret using Diffie-Hellman key exchange."""
        other_public_key_int = self.base64_to_int(other_public_key)
        other_private_key_int = self.base64_to_int(private_key)
        shared_secret_int = pow(other_public_key_int, other_private_key_int, prime)
        shared_secret = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, byteorder='big')
        derived_key = self.derive_key(shared_secret, salt, 32)
        return derived_key

    def derive_key(self, shared_secret, salt=None, key_length=32):
        """Derive a key from a shared secret using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            info=b'some_application_info',
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)

    def derive_encryption_keys(self, shared_secret):
        """Derive separate encryption and authentication keys from a shared secret."""
        encryption_key_hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # Length of the AES key
            salt=None,
            info=b'encryption',
            backend=default_backend()
        )
        encryption_key = encryption_key_hkdf.derive(shared_secret)
        authentication_key_hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # Length of the authentication key
            salt=None,
            info=b'authentication',
            backend=default_backend()
        )
        authentication_key = authentication_key_hkdf.derive(shared_secret)
        return encryption_key, authentication_key

    def derive_aes_key_from_shared_secret(self, shared_secret):
        """Derive an AES key from a shared secret."""
        key_size = 32
        salt = None
        info = b'X3DH AES key derivation'
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)

    def kdf(self, key, info):
        """Derive a key using HKDF with specified info."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(key)

    def generate_base_and_prime(self):
        """Generate a public/private key pair."""
        prime = self.generate_prime()
        generator = self.find_primitive_root(prime)
        return prime, generator

    def generate_key_pair(self, generator, prime):
        """Generate a one-time preKey for ephemeral key exchanges."""
        private_key = random.randint(2, prime - 1)
        public_key = self.calculate_public_key(prime, generator, private_key)
        return private_key, public_key

    def generate_key_pair_base64(self, generator, prime):
        """Generate a one-time preKey for ephemeral key exchanges."""
        private_key = random.randint(2, prime - 1)
        public_key = self.calculate_public_key(prime, generator, private_key)
        private_key_b64 = self.int_to_base64(private_key)
        public_key_b64 = self.int_to_base64(public_key)
        return private_key_b64, public_key_b64

    def generate_one_time_prekey(self, generator, prime):
        """Generate a one-time preKey for ephemeral key exchanges, int."""
        private_key = random.randint(2, prime - 1)
        public_key = self.calculate_public_key(prime, generator, private_key)
        key_id = os.urandom(16)
        return key_id, private_key, public_key

    def generate_one_time_prekey_base64(self, generator, prime):
        """Generate a one-time prekey for ephemeral key exchanges , base64."""
        private_key = random.randint(2, prime - 1)
        public_key = self.calculate_public_key(prime, generator, private_key)
        key_id = os.urandom(16)
        private_key_b64 = self.int_to_base64(private_key)
        public_key_b64 = self.int_to_base64(public_key)
        key_id_b64 = self.bytes_to_base64(key_id)

        return key_id_b64, private_key_b64, public_key_b64

    def combine_secrets(self, *secrets):
        """Combine multiple secrets into one using HKDF."""
        combined = b''.join(secrets)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'X3DH key agreement',
            backend=default_backend()
        )
        return hkdf.derive(combined)

    def generate_header_keys(self, shared_secret):
        """Generate sending and receiving header keys from a shared secret."""
        key_length = 32
        hkdf_sending = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=None,
            info=b'header_key_sending',
            backend=default_backend()
        )
        sending_header_key = hkdf_sending.derive(shared_secret)
        hkdf_receiving = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=None,
            info=b'header_key_receiving',
            backend=default_backend()
        )
        receiving_header_key = hkdf_receiving.derive(shared_secret)
        return sending_header_key, receiving_header_key

    def serialize_and_encode_key(self, key_integer):
        """Serialize and encode a key integer to base64."""
        key_bytes = key_integer.to_bytes((key_integer.bit_length() + 7) // 8, byteorder='big')
        # key_base64 = base64.urlsafe_b64encode(key_bytes).decode('utf-8')
        return key_bytes

    def int_to_base64(self, int_value):
        """Converts an integer to a base64-encoded string."""
        # Convert the integer to bytes
        value_bytes = int_value.to_bytes((int_value.bit_length() + 7) // 8, byteorder='big')
        # Encode the bytes to a base64 string
        base64_str = base64.b64encode(value_bytes).decode('utf-8')
        return base64_str

    def base64_to_int(self, base64_str):
        """Decodes a base64-encoded string back into an integer."""
        if not isinstance(base64_str, str):
            raise TypeError(f"Expected a base64 string, got {type(base64_str)} instead.")

        try:
            # Decode the base64 string to bytes
            value_bytes = base64.b64decode(base64_str)
        except ValueError as e:
            # Handle base64 decoding errors
            raise ValueError(f"Base64 decoding failed: {e}")

        # Convert the bytes back to an integer
        value_int = int.from_bytes(value_bytes, 'big')
        return value_int

    def bytes_to_base64(self, input_bytes):
        """Converts a byte array to a base64-encoded string."""
        base64_encoded_str = base64.b64encode(input_bytes).decode('utf-8')
        return base64_encoded_str
