from user_module.User import user
from diffiehellman_utils.dh_utils import DiffieHellmanUtils

def main():
    # Initialize users Alice and Bob
    dh_utils = DiffieHellmanUtils()
    alice = user("Alice", "http://127.0.0.1:5020", dh_utils, 5)
    bob = user("Bob", "http://127.0.0.1:5020", dh_utils, 5)

    # Alice and Bob register themselves with the relay server and publish their keys.
    alice.register()
    bob.register()

    # Alice fetches Bob's public keys from the relay server.
    bob_keys = alice.fetch_public_keys("Bob")

    # Alice performs X3DH key agreement to initiate a conversation with Bob.
    alice_shared_secret, alice_ephemeral_public_key = alice.perform_x3dh_key_agreement("Bob", bob_keys)

    # Alice sends an encrypted message to Bob using the shared secret derived from X3DH.
    alice_message = "Hello, Bob!"
    alice.send_message("Bob", alice_message)

    # Bob fetches messages from the relay server, decrypting any new messages.
    bob.fetch_messages()

    # Assuming Bob's fetch_messages method automatically handles X3DH on receiving Alice's initial message,
    # Bob now sends a reply back to Alice.
    bob_message = "Hi, Alice!"
    bob.send_message("Alice", bob_message)

    # Alice fetches messages from the relay server to see Bob's reply.
    alice.fetch_messages()


if __name__ == "__main__":
    main()