#!/usr/bin/env python
# coding: utf-8
#
import os
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class DiffieHellmanUtils:

    def is_prime(self, number):
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
        if prime_number == 2:
            return 1
        phi = prime_number - 1
        factors = self.find_factors(phi)
        for number in range(2, prime_number):
            if all(pow(number, phi // factor, prime_number) != 1 for factor in factors):
                return number
        return None

    def find_factors(self, number):
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
        while True:
            number = random.randint(min_value, max_value)
            if self.is_prime(number):
                return number

    def calculate_public_key(self, prime, generator, private_key):
        public_key = pow(generator, private_key, prime)
        return public_key

    def calculate_shared_secret(self, prime, other_public_key, private_key, salt=None):
        # Check if inputs are bytes and convert them to integers if necessary
        if isinstance(prime, bytes):
            prime = int.from_bytes(prime, byteorder='big')
        if isinstance(other_public_key, bytes):
            other_public_key = int.from_bytes(other_public_key, byteorder='big')
        if isinstance(private_key, bytes):
            private_key = int.from_bytes(private_key, byteorder='big')

        shared_secret_int = pow(other_public_key, private_key, prime)
        shared_secret = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, byteorder='big')
        derived_key = self.derive_key(shared_secret, None, 32)
        return derived_key

    def derive_key(self, shared_secret, salt=None, key_length=32):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            info=b'some_application_info'
        )
        key = hkdf.derive(shared_secret)
        return key

    def derive_encryption_keys(self, shared_secret):
        # Derive an encryption key
        encryption_key_hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # Length of the AES key
            salt=None,
            info=b'encryption',
            backend=default_backend()
            )
        encryption_key = encryption_key_hkdf.derive(shared_secret)

            # Derive an authentication key
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
        key = hkdf.derive(shared_secret)
        return key

    def kdf(self, key, info):

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend()
        )

        return hkdf.derive(key)

    def generate_base_and_prime(self):
        prime = self.generate_prime()
        generator = self.find_primitive_root(prime)
        return prime, generator

    def generate_key_pair(self, generator, prime):
        private_key = random.randint(2, prime - 1)
        public_key = self.calculate_public_key(prime, generator, private_key)

        return private_key, public_key

    def generate_one_time_preKey(self, generator, prime):
        private_key = random.randint(2, prime - 1)
        public_key = self.calculate_public_key(prime, generator, private_key)
        key_id = os.urandom(16)

        return key_id, private_key, public_key

    def combine_secrets(self, *secrets):
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
        key_length = 32
        hkdf_sending = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=None,
            info=b'header_key_sending',
            backend=default_backend()
        )
        sending_header_key = hkdf_sending.derive(shared_secret)

        # Generate a Header Key for receiving
        hkdf_receiving = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=None,
            info=b'header_key_receiving',
            backend=default_backend()
        )
        receiving_header_key = hkdf_receiving.derive(shared_secret)

        return sending_header_key, receiving_header_key

    def generate_signing_key_pair(self):
        return self.generate_key_pair(self.generator, self.prime)

