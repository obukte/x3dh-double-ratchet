import unittest
from src.DiffieHellmanUtils import DiffieHellmanUtils  # Adjust the import according to your project structure

class TestDHUtils(unittest.TestCase):

    def setUp(self):
        self.utils = DiffieHellmanUtils()

    def test_is_prime_with_prime_number(self):
        prime_numbers = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
        for num in prime_numbers:
            self.assertTrue(self.utils.is_prime(num), f"{num} should be prime")

    def test_is_prime_with_non_prime_number(self):
        non_prime_numbers = [1, 4, 6, 8, 9, 10, 12, 14, 15, 16]
        for num in non_prime_numbers:
            self.assertFalse(self.utils.is_prime(num), f"{num} should not be prime")

    def test_primitive_root_check(self):
        # This depends on known primitive roots
        # Example: For prime 7, 3 and 5 are primitive roots
        self.assertTrue(self.utils.is_primitive_root(3, 7))
        self.assertTrue(self.utils.is_primitive_root(5, 7))
        # 2 is not a primitive root of 7
        self.assertFalse(self.utils.is_primitive_root(2, 7))

    def test_generate_prime_within_range(self):
        for _ in range(10):  # Generate multiple times to ensure consistency
            prime = self.utils.generate_prime(50, 100)
            self.assertTrue(self.utils.is_prime(prime))
            self.assertTrue(50 <= prime <= 100, "Generated prime is not within the specified range")


if __name__ == '__main__':
    unittest.main()
