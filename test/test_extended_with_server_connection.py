# Assume diffie_hellman_utils.py is properly implemented and imported
from user_module.user import User
from diffiehellman_utils import DiffieHellmanUtils

def main():
    server_url = "http://127.0.0.1:5020"
    dh_utils = DiffieHellmanUtils()

    # Initialize Alice and Bob
    alice = User("Alice", server_url, dh_utils, max_one_time_prekeys=5)
    bob = User("Bob", server_url, dh_utils, max_one_time_prekeys=5)

    # Simulate Alice sending a secure message to Bob
    message_to_bob = "Hello, Bob! This is Alice."
    print(f"Alice is sending a secure message to Bob: '{message_to_bob}'")
    alice.send_message("Bob", message_to_bob)

    # Simulate Bob fetching and decrypting the message from Alice
    print("Bob is fetching his messages...")
    bob.fetch_messages()

if __name__ == "__main__":
    main()

