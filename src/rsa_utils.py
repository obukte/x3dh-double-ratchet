import random
from hashlib import sha256

class RSAUtils:
    def __init__(self):
        pass  # Assuming DiffieHellmanUtils is not needed for prime generation now

    def is_coprime(self, a, b):
        """Check if two numbers are coprime."""
        while b:
            a, b = b, a % b
        return a == 1

    def modinv(self, a, m):
        """Compute the modular multiplicative inverse of a modulo m."""
        m0, x0, x1 = m, 0, 1
        if m == 1:
            return 0
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        if x1 < 0:
            x1 += m0
        return x1

    def generate_small_prime(self, key_size):
        """Generate a smaller prime number for demonstration purposes."""
        # Smaller range for prime candidates
        start = 2**(key_size - 1)
        end = 2**key_size
        while True:
            num = random.randint(start, end)
            if self.is_prime(num):
                return num

    def is_prime(self, n, k=5):
        """Simple primality testing with adjustments for smaller numbers."""
        if n in (2, 3):
            return True
        if n <= 1 or n % 2 == 0:
            return False
        # Miller-Rabin test as before, possibly adjust for very small primes if necessary
        return self.miller_rabin(n, k)

    def generate_rsa_keys(self, key_size=512):  # Smaller default key size
        """Generate RSA key pair with smaller primes."""
        p = self.generate_small_prime(key_size // 2)
        q = self.generate_small_prime(key_size // 2)
        n = p * q
        phi = (p-1) * (q-1)

        e = 65537
        while not self.is_coprime(e, phi):
            e += 2

        d = self.modinv(e, phi)
        return {'public_key': (e, n), 'private_key': (d, n)}

    def hash_data(self, data):
        """Compute SHA-256 hash of the data."""
        return int.from_bytes(sha256(data.encode('utf-8')).digest(), byteorder='big')

    def sign(self, data, private_key):
        """Sign data using RSA private key."""
        hash_value = self.hash_data(data)
        d, n = private_key
        signature = pow(hash_value, d, n)
        return signature

    def verify(self, data, signature, public_key):
        """Verify RSA signature."""
        hash_value = self.hash_data(data)
        e, n = public_key
        hash_from_signature = pow(signature, e, n)
        return hash_value == hash_from_signature

    def miller_rabin(self, n, k=5):
        """Perform the Miller-Rabin primality test."""
        if n in (2, 3):
            return True
        if n <= 1 or n % 2 == 0:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
