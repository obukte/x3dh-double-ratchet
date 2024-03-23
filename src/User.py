#!/usr/bin/env python
# coding: utf-8

import os
from json import JSONDecodeError

import requests
import cryptography.exceptions
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .dh_utils import DiffieHellmanUtils
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

    def sign_prekey(self, signing_private_key, prekey_public):

        signature = (signing_private_key + prekey_public) % self.prime
        return signature

    def verify_signature(self, signing_public_key, prekey_public, signature):
        is_valid = (prekey_public - signature) % self.prime == 0
        return is_valid

    def register(self):
        url = f'{self.server_url}/register'
        data = {
            'user_id': self.name,
            'public_key': {
                'identity_key': base64.b64encode(self.int_to_bytes(self.identity_public)).decode('utf-8'),
                'signed_prekey': base64.b64encode(self.int_to_bytes(self.signed_prekey_public)).decode('utf-8'),
                'signed_prekey_signature': base64.b64encode(self.int_to_bytes(self.signed_prekey_signature)).decode('utf-8'),
                'one_time_prekeys': [base64.b64encode(self.int_to_bytes(public_key)).decode('utf-8') for _, _, public_key in self.one_time_prekeys]
            }
        }
        response = requests.post(url, json=data)

        if response.status_code == 201:
            print(f"User {self.name} registered successfully.")
            try:
                response_data = response.json()
                print(response_data)
            except JSONDecodeError:
                print("No JSON data in response")
        else:
            print(f"Failed to register {self.name}. Status code: {response.status_code}")
            print(f"Resonse text: ", response.text)

    def int_to_bytes(self, value):
        # Utility method to convert an integer to bytes
        return value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')

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
        if recipient_keys is None:
            print("Failed to fetch recipient's keys.")
            return

        if recipient_id not in self.shared_secrets:
            # No shared secret indicates this is the first message to this recipient
            # Perform X3DH key agreement to establish the initial shared secret
            shared_secret, ephemeral_public_key, chosen_prekey = self.perform_x3dh_key_agreement(recipient_id,
                                                                                                 recipient_keys)

            # Convert
            ephemeral_key = base64.b64encode(self.int_to_bytes(ephemeral_public_key)).decode('utf-8')
            chosen_prekey = base64.b64encode(self.int_to_bytes(chosen_prekey)).decode('utf-8')
            base64.b64encode(self.int_to_bytes(ephemeral_public_key)).decode('utf-8')

            initial_package = {
                'ephemeral_key': ephemeral_key,
                'chosen_prekey': chosen_prekey,
            }

        message_number = self.ratchet_states[recipient_id]['Ns']
        # Encrypt the message with the current sending chain key
        encrypted_message, nonce = self.encrypt_with_chain_key(recipient_id, message, message_number)

        # Prepare and send the data
        data = {
            'sender_id': self.name,
            'recipient_id': recipient_id,
            'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'message_number': message_number,
        }

        # If this is the first message, include the initial package information
        if initial_package is not None:
            data['initial_package'] = initial_package

        if self.should_perform_dh_ratchet(recipient_id):
            self.should_perform_dh_ratchet(recipient_id)
            # Include new DH public ket if a ratchet step was performed
            data['new_dh_public_key'] = self.ratchet_states[recipient_id]['DHs_public']

        response = requests.post(f'{self.server_url}/send_message', json=data)
        if response.status_code == 200:
            print("Message sent successfully.")
        else:
            print(f"Failed to send message: {response.json()}")

    def receive_message(self, sender_id, data):
        if sender_id not in self.ratchet_states:
            print(f"No ratchet state for {sender_id}. Unable to decrypt message.")
            return

        their_dh_public = self.ratchet_states[sender_id]['DHr']
        # get ciphertext from data
        ciphertext = base64.b64decode(data['encrypted_message'])
        nonce = base64.b64decode(data['nonce'])

        if not encrypted_message or not nonce or message_number is None:
            print("Missing data in the received message.")
            return

        # Extract message_number from the message data
        message_number = data.get('message_number')

        message_number = int(message_number)
        expected_message_number = self.ratchet_states[sender_id]['Nr']

        if message_number is None:
            print("Message number is missing in the received data.")
            return
        message_number = int(message_number)

        if 'new_dh_public_key' in data:
            # A new DH public ket indicates that the sender has performed a DH ratcher step
            new_dh_public_key = int(data['new_dh_public_key'], 16)
            self.perform_dh_ratchet_step(sender_id, new_dh_public_key)

        decrypted_message = None

        if message_number == expected_message_number:
            # Decrypt message with current chain key
            decrypted_message = self.decrypt_with_chain_key(sender_id, ciphertext, nonce,message_number)
            if decrypted_message is not None:
                self.ratchet_states[sender_id]['Nr'] += 1

        elif message_number > expected_message_number:
            # Attempt to decrypt with skipped message key
            decrypted_message = self.decrypt_skipped_message(sender_id, message_number, ciphertext,
                                                             nonce)

        if decrypted_message is not None:
            print(f"Received decrypted message from {sender_id}: {decrypted_message}")
            # Successfully decrypted, update receiving chain key
            self.update_receiving_chain_key(sender_id)
        else:
            # Handle decryption failure (possibly due to out-of order message)
            print("Failed to decrypt message, attempting to use skipped message keys")
            # Attempt to decrypt using skipped message keys if any
            decrypted_message = self.decrypt_skipped_message(sender_id, their_dh_public, message_number, ciphertext, nonce)
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

            if isinstance(chosen_prekey, str):
                chosen_prekey_public = int(chosen_prekey, 16)
            elif isinstance(chosen_prekey, int):
                chosen_prekey_public = chosen_prekey
            else:
                # Handle the case where chosen_prekey is None or another unexpected type
                # You will need to decide how to handle this in your application context
                chosen_prekey_public = None  # or some other default action
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

        kdf = HKDF(
            algorithm=hashes.SHA256(),  # Note the parentheses to instantiate SHA256
            length=96,  # Adjust length based on your needs
            salt=None,  # Typically, the salt can be None if not using one
            info=b'init double ratchet',  # This can be application specific information
            backend=default_backend()
        )

        key_material = kdf.derive(shared_secret)

        # Split the derived key material into the root key (RK), and two chain keys (CKs, CKr)
        rk, cks, ckr = key_material[:32], key_material[32:64], key_material[64:]

        self.ratchet_states[recipient_id] = {
            'DHr': their_dh_public,  # Their current DH public key
            'DHs': our_dh_public,  # Our current DH public key for sending
            'RK': rk,  # Root key to be derived
            'CKs': cks,  # Sending chain key
            'CKr': ckr,  # Receiving chain key
            'Ns': 0,  # Message number for sending
            'Nr': 0,  # Message number for receiving
            'PN': 0,  # Previous number of message in sending chain
            'MKSKIPPED': {}  # Dictionary for skipped message keys
        }
        # Log the initial ratchet state for debugging
        print(f"Ratchet state initialized for {recipient_id}: {self.ratchet_states[recipient_id]}")

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

    def handle_skipped_messages(self, sender_id, their_dh_public, message_number, message_key):

        if sender_id not in self.ratchet_states:
            self.ratchet_states[sender_id] = {'MKSKIPPED': {}}
        # Check if message keys for skipped messages have been stored
        if (their_dh_public, message_number) in self.ratchet_states[sender_id]['MKSKIPPED']:
            raise ValueError("Message key for this DH public key and message number already exists.")

        # Store the message key for later use
        self.ratchet_states[sender_id]['MKSKIPPED'][(their_dh_public, message_number)] = message_key

    def decrypt_skipped_message(self, sender_id, their_dh_public, message_number, ciphertext, nonce):
        # Check for existence of skipped messages for this sender
        if sender_id not in self.ratchet_states or 'MKSKIPPED' not in self.ratchet_states[sender_id]:
            print(f"No skipped messages for {sender_id}")
            return None

        # Retrieve the message key from MKSKIPPED if available using a composite key
        composite_key = (their_dh_public, message_number)
        message_key = self.ratchet_states[sender_id]['MKSKIPPED'].pop(composite_key, None)

        if message_key is None:
            print(f"Message key for skipped message not found {message_number} from {sender_id}")
            return None

        # Decrypt the message using the retrieved message key
        aesgcm = AESGCM(message_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception as e:
            print(f"Decryption of skipped message failed: {e}")
            return None

    def decrypt_with_chain_key(self, sender_id, their_dh_public, message_number, ciphertext, nonce):
        if sender_id not in self.ratchet_states:
            raise ValueError(f"No ratchet state for sender {sender_id}")

        if 'CKr' not in self.ratchet_states[sender_id] or 'Nr' not in self.ratchet_states[sender_id]:
            print(f"Receiving chain key or message number not initialized for {sender_id}.")
            return None

        current_message_number = self.ratchet_states[sender_id]['Nr']

        if message_number != current_message_number:
            print(
                f"Message number {message_number} does not match expected number {current_message_number}. Attempting to decrypt with skipped key.")
            return self.decrypt_skipped_message(sender_id, their_dh_public, message_number, ciphertext, nonce)

        # Use the current receiving chain key for decryption
        chain_key = self.ratchet_states[sender_id]['CKr']
        message_key, new_chain_key = self.derive_message_key(chain_key)

        aesgcm = AESGCM(message_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            # Successfully decrypted with the current receiving chain key
            # Update receiving chain key and increment message counter
            self.ratchet_states[sender_id]['CKr'] = new_chain_key
            self.ratchet_states[sender_id]['Nr'] += 1
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

        # Fetch the current message number before incrementing
        message_number = self.ratchet_states[recipient_id]['Ns']

        self.ratchet_states[recipient_id]['CKs'] = new_chain_key  # Update chain key
        self.ratchet_states[recipient_id]['Ns'] += 1  # Increment message count

        return ciphertext, nonce, message_number

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
