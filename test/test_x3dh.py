from src.User import User
from src.DiffieHellmanUtils import DiffieHellmanUtils

def main():
    # Initialize users Alice and Bob
    dh_utils = DiffieHellmanUtils()
    alice = User("Alice", "http://127.0.0.1:5020", dh_utils, 5)
    bob = User("Bob", "http://127.0.0.1:5020", dh_utils, 5)

    # Send messages to trigger DH ratchet update
    print("Alice sends message 1 to Bob")
    alice.send_message("Bob", "Message 1 from Alice to Bob")
    bob.fetch_messages()  # Bob receives Alice's first message

    print("Bob sends message 1 to Alice")
    bob.send_message("Alice", "Message 1 from Bob to Alice")
    alice.fetch_messages()  # Alice receives Bob's first message

    print("Alice sends message 2 to Bob (should trigger DH ratchet update)")
    alice.send_message("Bob", "Message 2 from Alice to Bob (trigger DH ratchet)")
    bob.fetch_messages()  # Bob receives Alice's second message, triggering DH ratchet update

    print("Bob sends message 2 to Alice (should trigger DH ratchet update)")
    bob.send_message("Alice", "Message 2 from Bob to Alice (trigger DH ratchet)")
    alice.fetch_messages()  # Alice receives Bob's second message, triggering DH ratchet update

    # Send additional messages to test the new DH ratchet
    print("Alice sends message 3 to Bob (after DH ratchet update)")
    alice.send_message("Bob", "Message 3 from Alice to Bob (after DH ratchet update)")
    bob.fetch_messages()  # Bob receives Alice's third message

    print("Bob sends message 3 to Alice (after DH ratchet update)")
    bob.send_message("Alice", "Message 3 from Bob to Alice (after DH ratchet update)")
    alice.fetch_messages()  # Alice receives Bob's third message

if __name__ == "__main__":
    main()