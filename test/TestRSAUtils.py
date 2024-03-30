import unittest
from src.rsa_utils import RSAUtils  # Make sure to replace this with the actual import

class TestRSAUtils(unittest.TestCase):
    def setUp(self):
        # Assuming you have a DiffieHellmanUtils instance named dh_utils
        # Initialize RSAUtils with it
        self.rsa_utils = RSAUtils()

    def test_rsa_sign_and_verify(self):
        # Sample data to sign
        data = "This is a test message".encode()

        # Generate RSA keys
        rsa_keys = self.rsa_utils.generate_rsa_keys()

        # Sign the data
        signature = self.rsa_utils.sign(data, rsa_keys['private_key'])
        self.assertIsInstance(signature, int, "Signature should be an integer")

        # Verify the signature
        verification_result = self.rsa_utils.verify(data, signature, rsa_keys['public_key'])
        self.assertTrue(verification_result, "Signature verification failed")

        # Modify the data and verify signature again to ensure failure on tampered data
        tampered_data = "This is a tampered message".encode()
        tampered_verification_result = self.rsa_utils.verify(tampered_data, signature, rsa_keys['public_key'])
        self.assertFalse(tampered_verification_result, "Signature verification erroneously succeeded on tampered data")

if __name__ == "__main__":
    unittest.main()
