import unittest
from src.rsa_utils import RSAUtils

class TestRSAUtils(unittest.TestCase):
    def setUp(self):
        """Setup for the tests."""
        self.rsa_utils = RSAUtils()
        self.key_size = 1024  # Using small key size for testing purposes

    def test_generate_rsa_keys(self):
        """Test RSA key generation."""
        keys = self.rsa_utils.generate_rsa_keys(self.key_size)
        self.assertIn('public_key', keys)
        self.assertIn('private_key', keys)

        # Check key lengths
        e, n = keys['public_key']
        d, n_prime = keys['private_key']
        self.assertEqual(n, n_prime)
        self.assertTrue(n.bit_length() <= self.key_size, "Modulus n should be less than or equal to the key size.")

    def test_sign_and_verify(self):
        """Test signing and verification."""
        keys = self.rsa_utils.generate_rsa_keys(self.key_size)
        print("keys: ", keys)
        data = "Hello, World!"
        signature = self.rsa_utils.sign(data, keys['private_key'])
        print("signed private: ", keys)

        # Verify signature
        self.assertTrue(self.rsa_utils.verify(data, signature, keys['public_key']), "Signature verification failed.")

        # Test verification failure with incorrect data
        self.assertFalse(self.rsa_utils.verify("Incorrect Data", signature, keys['public_key']), "Signature verification should fail with incorrect data.")

    def test_is_prime(self):
        """Test the primality test."""
        self.assertTrue(self.rsa_utils.is_prime(5), "5 should be recognized as a prime.")
        self.assertFalse(self.rsa_utils.is_prime(4), "4 should not be recognized as a prime.")

    def test_is_coprime(self):
        """Test coprimality."""
        self.assertTrue(self.rsa_utils.is_coprime(4, 9), "5 and 9 should be coprime.")
        self.assertFalse(self.rsa_utils.is_coprime(6, 8), "6 and 8 should not be coprime.")
        self.assertFalse(self.rsa_utils.is_coprime(14, 15), "14 and 15 should not be coprime.")
    def test_modinv(self):
        """Test modular inverse."""
        self.assertEqual(self.rsa_utils.modinv(3, 11), 4, "The modular inverse of 3 mod 11 should be 4.")

    def test_sign_and_verify(self):
        """Test signing and verification."""
        keys = self.rsa_utils.generate_rsa_keys(self.key_size)
        data = "Hello, World!"
        signature = self.rsa_utils.sign(data, keys['private_key'])

        # Verify signature
        self.assertTrue(self.rsa_utils.verify(data, signature, keys['public_key']), "Signature verification failed.")

        # Test verification failure with incorrect data
        self.assertFalse(self.rsa_utils.verify("Incorrect Data", signature, keys['public_key']),
                         "Signature verification should fail with incorrect data.")

    def test_signed_prekey_signature(self):
        """Test the creation and verification of a signed prekey."""
        # Assuming SPKB is the public part of Bob's signed prekey pair (again, RSA for example)
        spkb_public = self.bob_signed_prekey_keys['public_key']
        # Encode SPKB (serialization to bytes, simplified here)
        spkb_encoded = spkb_public[1].to_bytes((spkb_public[1].bit_length() + 7) // 8, byteorder='big')

        # Bob signs SPKB using his identity private key
        signature = self.rsa_utils.sign(spkb_encoded, self.bob_identity_keys['private_key'])

        # Verification of the signature using Bob's public identity key
        verification_result = self.rsa_utils.verify(spkb_encoded, signature, self.bob_identity_keys['public_key'])
        self.assertTrue(verification_result,
                        "The signature of SPKB should be verifiable with Bob's identity public key.")

if __name__ == "__main__":
    unittest.main()
