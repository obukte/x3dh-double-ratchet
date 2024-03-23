#!/usr/bin/env python
# coding: utf-8

import os
import requests
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from diffiehellman_utils.dh_utils import DiffieHellmanUtils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from datetime import time

dh_utils = DiffieHellmanUtils()
name = "User1"
server_url = "http://127.0.0.1:5020"
DH_RATCHET_UPDATE_THRESHOLD = 2


class User:

    def __init__(self, name, server_url, dh_utils, max_one_time_prekeys=5):
        self.name = name
        self.dh_utils = dh_utils
        self.server_url = server_url
        self.max_one_time_prekeys = max_one_time_prekeys
        self.shared_secrets = {}
        self.ratchet_states = {}
        self.initialize_keys()

        self.one_time_prekey_private = [private for _, private, _ in self.one_time_prekeys]

        self.register()

    def initialize_keys(self):
        self.prime, self.generator = self.fetch_dh_parameters()
        self.identity_private, self.identity_public = self.dh_utils.generate_key_pair(self.generator, self.prime)
        self.signed_prekey_private, self.signed_prekey_public = self.dh_utils.generate_key_pair(self.generator,
                                                                                                self.prime)
        self.one_time_prekeys = [self.dh_utils.generate_one_time_preKey(self.generator, self.prime) for _ in
                                 range(self.max_one_time_prekeys)]
        self.signed_prekey_signature = self.sign_prekey(self.identity_private, self.signed_prekey_public)

        self.key_bundle = {
            'identity_key': self.identity_public,
            'signed_prekey': self.signed_prekey_public,
            'signed_prekey_signature': self.signed_prekey_signature,
            'one_time_prekeys': [public_key for _, _, public_key in self.one_time_prekeys]  # List of one-time prekeys
        }

    def fetch_dh_parameters(self):
        response = requests.get(f'{self.server_url}/dh_parameters')
        if response.status_code == 200:
            dh_params = response.json()
            return dh_params['prime'], dh_params['generator']
        else:
            raise Exception("Failed to fetch DH parameters from the server.")

    def fetch_public_keys(self, user_id):
        url = f'{self.server_url}/get_keys/{user_id}'
        response = requests.get(url)
        if response.status_code == 200:
            public_keys = response.json()

            # Check if the server indicates that rekeying is needed
            if public_keys.get('rekey_needed', False):
                print("Server indicates that rekeying is needed. Generating and uploading new one-time prekeys.")
                self.generate_and_upload_new_prekeys()

            return {
                'identity_key': public_keys['identity_key'],
                'signed_prekey': public_keys['signed_prekey'],
                'one_time_prekey': public_keys.get('one_time_prekey')
            }
        else:
            print(f"Failed to fetch keys for {user_id}")
            return None

    def fetch_messages(self):
        """Fetch new messages from the server and process them using receive_message."""
        url = f'{self.server_url}/fetch_messages/{self.name}'
        response = requests.get(url)
        if response.status_code == 200:
            messages = response.json().get('messages', [])
            for message in messages:
                self.receive_message(message['sender_id'], message)
        else:
            print("Failed to fetch messages:", response.json())

    def start_polling_for_messages(self, interval=5):
        """Start polling the server for messages at a specified interval (in seconds)."""
        print(f"Starting to poll for messages every {interval} seconds...")
        try:
            while True:
                self.fetch_messages()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("Stopped polling for messages.")

    def sign_prekey(self, private_key, prekey_public_bytes):
        signature = private_key.sign(
            prekey_public_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, public_key, prekey_public_bytes, signature):
        try:
            public_key.verify(
                signature,
                prekey_public_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False

    def register(self):
        url = f'{self.server_url}/register'
        data = {
            'user_id': self.name,
            'public_key': {
                'identity_key': str(self.identity_public),
                'signed_prekey': str(self.signed_prekey_public),
                'signed_prekey_signature': self.signed_prekey_signature.hex(),
                'one_time_prekeys': [str(public_key) for _, _, public_key in self.one_time_prekeys]
            }
        }
        response = requests.post(url, json=data)
        if response.status_code == 201:
            print(f"User {self.name} registered successfully.")
        else:
            print(f"Failed to register {self.name}: {response.json()}")

    def generate_and_upload_new_prekeys(self):
        self.one_time_prekeys = [self.dh_utils.generate_one_time_preKey(self.generator, self.prime) for _ in
                                 range(self.max_one_time_prekeys)]
        one_time_prekeys_public = [public for _, _, public in self.one_time_prekeys]

        data = {
            'user_id': self.name,
            'public_key': {
                'one_time_prekeys': [str(public_key) for public_key in one_time_prekeys_public]
            }
        }

        response = requests.post(f'{self.server_url}/update_prekeys', json=data)
        if response.status_code == 200:
            print("New one-time prekeys uploaded successfully.")
        else:
            print("Failed to upload new one-time prekeys.")

    def send_message(self, recipient_id, message):
        recipient_keys = self.fetch_public_keys(recipient_id)
        initial_package = None
        if recipient_keys in None:
            print("Failed to fetch recipient's keys.")
            return

        if recipient_id not in self.shared_secrets:
            # No shared secret indicates this is the first message to this recipient
            # Perform X3DH key agreement to establish the initial shared secret
            shared_secret, ephemeral_public_key, chosen_prekey = self.perform_x3dh_key_agreement(recipient_id,
                                                                                                 recipient_keys)

            # Initiate the double ratchet mechanism with the established shared secret
            self.initiate_double_ratchet(recipient_id, shared_secret, ephemeral_public_key,
                                         recipient_keys['identity_key'])

            initial_package = {
                'ephemeral_key': ephemeral_public_key.hex(),
                'chosen_prekey': chosen_prekey.hex(),
            }

        # Encrypt the message with the current sending chain key
        encrypted_message, nonce = self.encrypt_with_chain_key(recipient_id, message)

        # Prepare and send the data
        data = {
            'sender_id': self.name,
            'recipient_id': recipient_id,
            'encrypted_message': encrypted_message.hex(),
            'nonce': nonce.hex(),
        }

        # If this is the first message, include the initial package information
        if initial_package is not None:
            data['initial_package'] = initial_package

        if self.should_perform_dh_ratchet(recipient_id):
            self.should_perform_dh_ratchet(recipient_id)
            # Include new DH public ket if a ratchet step was performed
            data['new_dh_public_key'] = self.ratchet_states[recipient_id]['DHs_public'].hex()

        response = requests.post(f'{self.server_url}/send_message', json=data)
        if response.status_code == 200:
            print("Message sent successfully.")
        else:
            print(f"Failed to send message: {response.json()}")

    def receive_message(self, sender_id, data):
        if sender_id not in self.ratchet_states:
            print(f"No ratchet state for {sender_id}. Unable to decrypt message.")
            return

        if 'new_dh_public_key' in data:
            # A new DH public ket indicates that the sender has performed a DH ratcher step
            new_dh_public_key = int(data['new_dh_public_key'], 16)
            self.perform_dh_ratchet_step(sender_id, new_dh_public_key)

        encrypted_message = bytes.fromhex(data['encrypted_message'])
        nonce = bytes.fromhex(data['nonce'])

        # Decrypt the message using the current receiving chain key
        decrypted_message = self.decrypt_with_chain_key(sender_id, encrypted_message, nonce)
        if decrypted_message is not None:
            print(f"Received decrypted message from {sender_id}: {decrypted_message}")
            # Successfully decrypted, update receiving chain key
            self.update_receiving_chain_key(sender_id)
        else:
            # Handle decryption failure (possibly due to out-of order message)
            print("Failed to decrypt message, attempting to use skipped message keys")
            # Attempt to decrypt using skipped message keys if any
            decrypted_message = self.decrypt_skipped_message(sender_id, data)
            if decrypted_message:
                print(f"Received decrypted message {sender_id} using skipped key: {decrypted_message}")
            else:
                print("Failed to decrypt message using skipped keys")

    def update_receiving_chain_key(self, sender_id):
        # Update the receiving chain key (CKr) using KDF and increment Nr
        chain_key = self.ratchet_states[sender_id]['CKr']
        _, new_chain_key = self.derive_message_key(chain_key)
        self.ratchet_states[sender_id]['CKr'] = new_chain_key
        self.ratchet_states[sender_id]['Nr'] += 1

    def derive_message_key(self, chain_key):
        # Use HKDF to derive new keys from the chain key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # Length for a new message key and a new chain key
            salt=None,
            info=b'message_key_derivation',
            backend=default_backend()
        )

        key_material = hkdf.derive(chain_key)

        # Split the derived key material into a message key and a new chain key
        message_key = key_material[:32]  # First half for the message key
        new_chain_key = key_material[32:]  # Second half for the new chain key

        return message_key, new_chain_key

    def perform_x3dh_key_agreement(self, recipient_id, recipient_keys):

        chosen_prekey = None
        ephemeral_private_key, ephemeral_public_key = self.dh_utils.generate_key_pair(self.generator, self.prime)

        DH1 = self.dh_utils.calculate_shared_secret(self.prime, self.identity_private, recipient_keys['signed_prekey'])
        DH2 = self.dh_utils.calculate_shared_secret(self.prime, self.signed_prekey_private,
                                                    recipient_keys['identity_key'])
        DH3 = self.dh_utils.calculate_shared_secret(self.prime, ephemeral_private_key, recipient_keys['signed_prekey'])

        # Check if a one-time prekey is provided
        if 'one_time_prekey' in recipient_keys and recipient_keys['one_time_prekey']:
            chosen_prekey = recipient_keys['one_time_prekey']
            chosen_prekey_public = int(chosen_prekey, 16)
            DH4 = self.dh_utils.calculate_shared_secret(self.prime, ephemeral_private_key, chosen_prekey_public)
        else:
            # Handle the case where no one-time prekey is left or provided
            print("Warning: No one-time prekey available. This might affect forward secrecy.")
            DH4 = 0  # Proceed without the contribution of a one-time prekey

        # Combine the DH secrets to derive the shared secret
        shared_secret = self.dh_utils.combine_secrets(DH1, DH2, DH3, DH4)

        self.shared_secrets[recipient_id] = shared_secret
        self.initiate_double_ratchet(recipient_id, shared_secret, ephemeral_public_key, recipient_keys['identity_key'])

        return shared_secret, ephemeral_public_key, chosen_prekey if 'one_time_prekey' in recipient_keys else None

    def initiate_double_ratchet(self, recipient_id, shared_secret, our_dh_public, their_dh_public):
        """
                Initiates the double ratchet mechanism by setting the initial ratchet keys and states.

                :param recipient_id: ID of the recipient user.
                :param shared_secret: The shared secret derived from the X3DH key agreement.
                :param our_dh_public: Our current DH public key.
                :param their_dh_public: Their current DH public key (from the X3DH agreement).
        """
        self.ratchet_states[recipient_id] = {
            'DHr': their_dh_public,  # Their current DH public key
            'RK': None,  # Root key to be derived
            'CKs': None,  # Sending chain key
            'CKr': None,  # Receiving chain key
            'Ns': 0,  # Message number for sending
            'Nr': 0,  # Message number for receiving
            'PN': 0,  # Previous number of message in sending chain
            'MKSKIPPED': {}  # Dictionary for skipped message keys
        }

        # Derive the first root key (RK) and the first pair of chain keys (CKs, CKr) using HKDF
        kdf = HKDF(algorithm=hashes.SHA256, length=96, salt=None, info=b'init double ratchet',
                   backend=default_backend())
        rk, cks, ckr = kdf.derive(shared_secret)

        # Split the derived data
        self.ratchet_states[recipient_id]['RK'] = rk[:32]
        self.ratchet_states[recipient_id]['CKs'] = cks[32:64]
        self.ratchet_states[recipient_id]['CKr'] = ckr[64:]

        # Store our DH public key for sending to recipient

        self.ratchet_states[recipient_id]['DHs_public'] = our_dh_public

    def perform_dh_ratchet_step(self, recipient_id, their_dh_public):
        # Generate new DH key pair
        our_new_dh_private, our_new_dh_public = self.dh_utils.generate_key_pair(self.generator, self.prime)

        # Derive new shared secret from our new private key and their public key
        new_shared_secret = self.dh_utils.calculate_shared_secret(self.prime, our_new_dh_private, their_dh_public)

        # Update the root key (RK) and derive new chain keys (CKs, CKr) using the new shared secret
        rk, cks, ckr = self.derive_new_rk_and_chain_keys(new_shared_secret, self.ratchet_states[recipient_id]['RK'])

        # Update ratchet state
        self.ratchet_states[recipient_id].update({
            'DHr': their_dh_public,
            'DHs': our_new_dh_public,
            'RK': rk,
            'CKs': cks,
            'CKr': ckr,
            'Ns': 0,
            'Nr': 0,
            'PN': 0,
            'MKSKIPPED': {}
        })

    def should_perform_dh_ratchet(self, recipient_id):
        if recipient_id not in self.ratchet_states:
            return False
        message_count = self.ratchet_states[recipient_id]['Ns']
        if message_count >= DH_RATCHET_UPDATE_THRESHOLD:
            return True
        return False

    def handle_skipped_messages(self, sender_id, message_number, their_dh_public, message_key):
        # Check if message keys for skipped messages have been stored
        if (their_dh_public, message_number) in self.ratchet_states[sender_id]['MKSKIPPED']:
            raise ValueError("Message key for this DH public key and message number already exists.")

        # Store the message key for later use
        self.ratchet_states[sender_id]['MKSKIPPED'][(their_dh_public, message_number)] = message_key

    def decrypt_skipped_message(self, sender_id, their_dh_public, message_number, ciphertext, nonce):
        # Retrieve the message key from MKSKIPPED if available
        message_key = self.ratchet_states[sender_id]['MKSKIPPED'].pop((their_dh_public, message_number), None)

        if message_key is None:
            raise ValueError("Message key for skipped message not found.")

        # Decrypt the message using the retrieved message key
        aesgcm = AESGCM(message_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception as e:
            print(f"Decryption of skipped message failed: {e}")
            return None

    def decrypt_with_chain_key(self, sender_id, ciphertext, nonce):
        if sender_id not in self.ratchet_states:
            raise ValueError(f"No ratchet state for sender {sender_id}")

        chain_key = self.ratchet_states[sender_id]['CKr']
        message_key, new_chain_key = self.derive_message_key(chain_key)

        aesgcm = AESGCM(message_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            self.ratchet_states[sender_id]['CKr'] = new_chain_key  # Update receiving chain key
            self.ratchet_states[sender_id]['Nr'] += 1  # Increment the receiving message counter
            return plaintext.decode()
        except cryptography.exceptions.InvalidKey as e:
            print(f"Decryption failed due to an Invalid tag: {str(e)}")
            return None
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
            return None

    def encrypt_with_chain_key(self, recipient_id, plaintext):
        if recipient_id not in self.ratchet_states:
            raise ValueError(f"No ratchet state for recipient {recipient_id}")

        chain_key = self.ratchet_states[recipient_id]['CKs']
        message_key = dh_utils.kdf(chain_key, b'message_key')  # Derive message key from chain key
        new_chain_key = dh_utils.kdf(chain_key, b'next_chain_key')  # Derive new chain key

        aesgcm = AESGCM(message_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

        self.ratchet_states[recipient_id]['CKs'] = new_chain_key  # Update chain key
        self.ratchet_states[recipient_id]['Ns'] += 1  # Increment message count

        return ciphertext, nonce

    def derive_new_rk_and_chain_keys(self, shared_secret, old_root_key):
        # Use HKDF to derive 96 bytes of key material from the shared secret and old root key.
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=96,  # 32 for RK, 32 for CKs, 32 for CKr
            salt=old_root_key,  # Use the old root key as salt
            info=b'new_rk_and_chain_keys',
            backend=default_backend()
        )

        key_material = hkdf.derive(shared_secret)
        new_root_key = key_material[:32]
        new_sending_chain_key = key_material[32:64]
        new_receiving_chain_key = key_material[64:96]

        return new_root_key, new_sending_chain_key, new_receiving_chain_key
