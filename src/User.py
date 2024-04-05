#!/usr/bin/env python
# coding: utf-8

import os
from json import JSONDecodeError

import requests
import cryptography.exceptions
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.DiffieHellmanUtils import DiffieHellmanUtils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from datetime import time

name = "User1"
server_url = "http://127.0.0.1:5020"
DH_RATCHET_UPDATE_THRESHOLD = 10


class User:

    def __init__(self, name, server_url, max_one_time_prekeys=20):
        self.name = name
        self.dh_utils = DiffieHellmanUtils()
        self.server_url = server_url
        self.max_one_time_prekeys = max_one_time_prekeys
        self.shared_secrets = {}
        self.ratchet_states = {}
        self.initialize_keys()

        self.one_time_prekey_private = [private for _, private, _ in self.one_time_prekeys]

        self.register()

    def initialize_keys(self):
        self.prime, self.generator = self.fetch_dh_parameters()
        self.identity_private, self.identity_public = self.dh_utils.generate_key_pair_base64(self.generator, self.prime)
        self.signed_prekey_private, self.signed_prekey_public = self.dh_utils.generate_key_pair_base64(self.generator, self.prime)


        # unique_one_time_prekeys = []
        # public_key_set = set()
        #
        # # Continue generating one-time prekeys until the desired number of unique keys have been created
        # while len(unique_one_time_prekeys) < self.max_one_time_prekeys:
        #     key_id_b64, private_key_b64, public_key_b64 = self.dh_utils.generate_one_time_prekey_base64(self.generator,
        #                                                                                                 self.prime)
        #
        #     # Check if the public key component is unique
        #     if public_key_b64 not in public_key_set:
        #         public_key_set.add(public_key_b64)
        #         unique_one_time_prekeys.append((key_id_b64, private_key_b64, public_key_b64))
        #
        # self.one_time_prekeys = unique_one_time_prekeys


        self.one_time_prekeys = [self.dh_utils.generate_one_time_prekey_base64(self.generator, self.prime) for _ in
                                 range(self.max_one_time_prekeys)]

        print(f"{self.name} initialized total of: {len(self.one_time_prekeys)} keys. here are they:  {self.one_time_prekeys}")

        key_bundle = {
            'identity_key': self.identity_public,
            'signed_prekey': self.signed_prekey_public,
            'one_time_prekeys': [public_key for _, _, public_key in self.one_time_prekeys]  # List of one-time prekeys
        }

        print("User: ", self.name, " initialized keys: ", key_bundle)

    def fetch_dh_parameters(self):
        response = requests.get(f'{self.server_url}/dh_parameters')
        if response.status_code == 200:
            dh_params = response.json()
            print(f"{self.name} fetched dh parameters from server: prime: {dh_params['prime']} generator: {dh_params['generator']} ")
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
                print(f"Server indicates to {self.name} that rekeying is needed. Generating and uploading new one-time prekeys.")
                self.generate_and_upload_new_prekeys()

            print(f"User {self.name} fetched public keys for {user_id}: {public_keys}")
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
                print(f"Processing message from {message['sender_id']}: {message}")
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


    def register(self):
        url = f'{self.server_url}/register'
        data = {
            'user_id': self.name,
            'public_key': {
                'identity_key': self.identity_public,
                'signed_prekey': self.signed_prekey_public,
                'one_time_prekeys': [{'key_id':key_id, 'public_key':public_key} for key_id, _, public_key in self.one_time_prekeys]
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

    def generate_and_upload_new_prekeys(self):
        self.one_time_prekeys = [self.dh_utils.generate_one_time_prekey_base64(self.generator, self.prime) for _ in
                                 range(self.max_one_time_prekeys)]
        data = {
            'user_id': self.name,
            'public_key': {
                'one_time_prekeys': [public for _, _, public in self.one_time_prekeys]
            }
        }

        response = requests.post(f'{self.server_url}/update_prekeys', json=data)
        if response.status_code == 200:
            print("New one-time prekeys uploaded successfully.")
        else:
            print("Failed to upload new one-time prekeys.")

    def get_one_time_prekey_private_by_id(self, key_id_base64):
        """Retrieve the private part of a one-time prekey given its public part."""
        print(f"Looking for one-time prekey with ID: {key_id_base64}")
        for key_id_b64, private_key_b64, public_key_b64 in self.one_time_prekeys:
            print(f"Checking against stored key ID: {key_id_b64}")
            if key_id_b64 == key_id_base64:
                print(f"Match found. Key ID: {key_id_b64}")
                return private_key_b64
        print("No matching one-time prekey found.")
        return None

    def send_message(self, recipient_id, message):
        recipient_keys = self.fetch_public_keys(recipient_id)
        initial_package = None
        if recipient_keys is None:
            print("Failed to fetch recipient's keys.")
            return

        if recipient_id not in self.shared_secrets or self.should_perform_dh_ratchet(recipient_id):
            print(f"{self.name} doesn't have {recipient_id} in shared secretes?")
            # No shared secret indicates this is the first message to this recipient
            # Perform X3DH key agreement to establish the initial shared secret
            shared_secret, ephemeral_public_key, chosen_prekey_id = self.perform_x3dh_key_agreement(recipient_id,
                                                                                                 recipient_keys)

            initial_package = {
                'ephemeral_key': ephemeral_public_key,
                'chosen_prekey_id': chosen_prekey_id
            }

        # Encrypt the message with the current sending chain key
        encrypted_message, nonce, message_number = self.encrypt_with_chain_key(recipient_id, message)

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

        print(f"Sending message to {recipient_id}. Message number: {message_number}")
        response = requests.post(f'{self.server_url}/send_message', json=data)
        if response.status_code == 200:
            print("Message sent successfully.")
        else:
            print(f"Failed to send message: {response.json()}")

    def receive_message(self, sender_id, data):
        print(f"Attempting to decrypt message at: {self.name}from {sender_id}")
        if sender_id not in self.ratchet_states:
            print(f"{self.name} has no ratchet state for {sender_id}. Starting setup_initial_ratchet_state().")
            self.handle_x3dh_and_initiate_double_ratchet(data)

        # get ciphertext from data
        ciphertext = data['encrypted_message']
        nonce = data['nonce']

        # Convert message number from string to integer
        try:
            message_number = int(data.get('message_number'))
        except (ValueError, TypeError):
            print("Invalid message number received.")
            return

        if not ciphertext or not nonce or message_number is None:
            print("Missing data in the received message.")
            return

        expected_message_number = self.ratchet_states[sender_id]['Nr']

        # if 'new_dh_public_key' in data:
        #     # A new DH public ket indicates that the sender has performed a DH ratcher step
        #     print(f"New DH public key received from {sender_id}. Performing DH ratchet step.")
        #     new_dh_public_key = data['new_dh_public_key']
        #     self.perform_dh_ratchet_step(sender_id, new_dh_public_key)

        decrypted_message = None
        if message_number == expected_message_number:
            # Decrypt message with current chain key
            decrypted_message = self.decrypt_with_chain_key(sender_id, message_number, ciphertext, nonce)
            if decrypted_message is not None:
                self.ratchet_states[sender_id]['Nr'] += 1

        elif message_number > expected_message_number:
            # Attempt to decrypt with skipped message key
            decrypted_message = self.decrypt_skipped_message(sender_id,message_number, ciphertext, nonce)

        if decrypted_message is not None:
            print(f"\n---------------\nReceived message and decrypted from {sender_id} !!!! decrypted message: {decrypted_message}\n---------------\n")
        else:
            # Handle decryption failure (possibly due to out-of order message)
            print("Failed to decrypt message, attempting to use skipped message keys")
            # Attempt to decrypt using skipped message keys if any
            decrypted_message = self.decrypt_skipped_message(sender_id,  message_number, ciphertext, nonce)
            if decrypted_message:
                print(f"Received decrypted message {sender_id} using skipped key: {decrypted_message}")
            else:
                print("Failed to decrypt message using skipped keys")

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

    def derive_ratchet_key(self, shared_secret):
        """Derive a key from a shared secret using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ratchet_key_derivation',
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)

    def perform_x3dh_key_agreement(self, recipient_id, recipient_keys):

        chosen_prekey_id = None

        # Generate ephemeral key pair
        ephemeral_private_key, ephemeral_public_key = self.dh_utils.generate_key_pair_base64(self.generator, self.prime)

        DH1 = self.dh_utils.calculate_shared_secret_base64(self.prime, self.identity_private, recipient_keys['signed_prekey'])
        DH2 = self.dh_utils.calculate_shared_secret_base64(self.prime, ephemeral_private_key, recipient_keys['identity_key'])
        DH3 = self.dh_utils.calculate_shared_secret_base64(self.prime, ephemeral_private_key, recipient_keys['signed_prekey'])


        print(f"{self.name} created ephemeral keys for communications: private: {self.dh_utils.base64_to_int(ephemeral_private_key)} public: {self.dh_utils.base64_to_int(ephemeral_public_key)}")

        print(
            f"{self.name} is performing X3DH key agreement with {recipient_id}. {self.name}'s new 'ephemeral_public_key': {ephemeral_public_key}, 'identity_private':{self.identity_private}, 'signed_prekey_private': {self.signed_prekey_private} )")
        print(
            f"\t-DH1-{self.name}'s identity_private: {self.dh_utils.base64_to_int(self.identity_private)} with {recipient_id}'s signed_prekey: {self.dh_utils.base64_to_int(recipient_keys['signed_prekey'])}")
        print(
            f"\t-DH2-{self.name}'s ephemeral_private_key:{self.dh_utils.base64_to_int(ephemeral_private_key)} with {recipient_id}'s identity_key: {self.dh_utils.base64_to_int(recipient_keys['identity_key'])}")
        print(
            f"\t-DH3-{self.name}'s ephemeral_private_key: {self.dh_utils.base64_to_int(ephemeral_private_key)} with {recipient_id}'s signed_prekey: {self.dh_utils.base64_to_int(recipient_keys['signed_prekey'])}")
        print(f"\tDH1 CALCULATED VALUE: {self.dh_utils.base64_to_int(self.dh_utils.bytes_to_base64(DH1))}")
        print(f"\tDH2 CALCULATED VALUE: {self.dh_utils.base64_to_int(self.dh_utils.bytes_to_base64(DH2))}")
        print(f"\tDH3 CALCULATED VALUE: {self.dh_utils.base64_to_int(self.dh_utils.bytes_to_base64(DH3))}")

        # Optional DH4
        DH4 = None

        # Check if a one-time prekey is provided
        if 'one_time_prekey' in recipient_keys and recipient_keys['one_time_prekey']:
            chosen_prekey_bundle = recipient_keys['one_time_prekey'][0]
            chosen_prekey = chosen_prekey_bundle['public_key']
            chosen_prekey_id = chosen_prekey_bundle['key_id']
            DH4 = self.dh_utils.calculate_shared_secret_base64(self.prime, ephemeral_private_key, chosen_prekey)
            print(f"\t-DH4-{self.name}'s ephemeral_private_key: {self.dh_utils.base64_to_int(ephemeral_private_key)} and {recipient_id}'s chosen_prekey_public: {self.dh_utils.base64_to_int(chosen_prekey)}")
            print(f"\tDH4 CALCULATED VALUE: {self.dh_utils.base64_to_int(self.dh_utils.bytes_to_base64(DH4))}")
        else:
            print(f"{self.name} did not used one-time prekey used for X3DH with: ", recipient_id)

        # Combine the DH secrets to derive the shared secret
        shared_secret_components = [DH1, DH2, DH3] + ([DH4] if DH4 else [])
        shared_secret = self.dh_utils.combine_secrets(*shared_secret_components)
        print(f"{self.name} combined shared secret for {recipient_id}, secret_shared: {shared_secret.hex()}")

        # Verify shared_secret is in bytes format after combination
        if not isinstance(shared_secret, bytes):
            print(f":perform_x3dh_key_agreement: Shared secret must be bytes, but it is {type(shared_secret)}")
            # Corrective action as needed or return to stop execution
            shared_secret = b''

        self.shared_secrets[recipient_id] = shared_secret
        self.initiate_double_ratchet(recipient_id, shared_secret, ephemeral_public_key, recipient_keys['identity_key'])

        return shared_secret, ephemeral_public_key, chosen_prekey_id if chosen_prekey_id else None

    def handle_x3dh_and_initiate_double_ratchet(self, data):
        sender_id = data['sender_id']
        initial_package = data.get('initial_package', {})

        print(f"{self.name} started x3dh initiation for decryption, data package: {data}")

        # Extract ephemeral public key and chosen prekey from the initial package
        ephemeral_public_key = initial_package.get('ephemeral_key')
        chosen_prekey_id = initial_package.get('chosen_prekey_id')

        print(f"ephemeral_public_key_base64: {ephemeral_public_key} chosen_prekey: {chosen_prekey_id}")

        # Fetch Alice's public keys if not already available
        recipient_keys = self.fetch_public_keys(sender_id)
        if not recipient_keys:
            print(f"Unable to fetch public keys for {sender_id}. Cannot proceed with X3DH.")
            return None


        # Perform the necessary DH calculations
        DH1 = self.dh_utils.calculate_shared_secret_base64(self.prime,  self.signed_prekey_private, recipient_keys['identity_key'])
        DH2 = self.dh_utils.calculate_shared_secret_base64(self.prime, self.identity_private, ephemeral_public_key)
        DH3 = self.dh_utils.calculate_shared_secret_base64(self.prime, self.signed_prekey_private, ephemeral_public_key)

        print(f"\tDH1 CALCULATED VALUE: {self.dh_utils.base64_to_int(self.dh_utils.bytes_to_base64(DH1))}")
        print(f"\tDH2 CALCULATED VALUE: {self.dh_utils.base64_to_int(self.dh_utils.bytes_to_base64(DH2))}")
        print(f"\tDH3 CALCULATED VALUE: {self.dh_utils.base64_to_int(self.dh_utils.bytes_to_base64(DH3))}")
        print(
            f"\t-DH1-{self.name}'s signed_prekey_private: {self.dh_utils.base64_to_int(self.signed_prekey_private)} with {sender_id}'s identity_key: {self.dh_utils.base64_to_int(recipient_keys['identity_key'])}")
        print(
            f"\t-DH2-{self.name}'s identity_private:{self.dh_utils.base64_to_int(self.identity_private)} with {sender_id}'s ephemeral_public_key: {self.dh_utils.base64_to_int(ephemeral_public_key)}")
        print(
            f"\t-DH3-{self.name}'s signed_prekey_privatey: {self.dh_utils.base64_to_int(self.signed_prekey_private)} with {sender_id}'s ephemeral_public_key: {self.dh_utils.base64_to_int(ephemeral_public_key)}")

        DH4 = None
        if chosen_prekey_id:
            # If a one-time prekey was used, perform the DH calculation
            one_time_prekey_private = self.get_one_time_prekey_private_by_id(chosen_prekey_id)
            if one_time_prekey_private is None:
                print(f"one_time_prekey_private is None ")
            else:
                DH4 = self.dh_utils.calculate_shared_secret_base64(self.prime,  one_time_prekey_private, ephemeral_public_key)
                print(f"\t-DH4-{self.name}'s one_time_prekey_private: {self.dh_utils.base64_to_int(one_time_prekey_private)} and {sender_id}'s ephemeral_public_key: {self.dh_utils.base64_to_int(ephemeral_public_key)}")
                print(f"\tDH4 CALCULATED VALUE: {self.dh_utils.base64_to_int(self.dh_utils.bytes_to_base64(DH4))}")

        # Combine the DH results to derive the shared secret
        shared_secret_components = [DH1, DH2, DH3] + ([DH4] if DH4 else [])
        shared_secret = self.dh_utils.combine_secrets(*shared_secret_components)
        print(f"{self.name} combined shared secret for {sender_id}, secret_shared: {shared_secret.hex()}")

        # add derived new secret to shared secrets
        self.shared_secrets[sender_id] = shared_secret
        # Initialize or update the double ratchet mechanism
        self.initiate_double_ratchet_received(sender_id, shared_secret, ephemeral_public_key, recipient_keys['identity_key'])

    def initiate_double_ratchet(self, recipient_id, shared_secret, our_dh_public, their_dh_public):
        print(
            f"{self.name} is Initializing Double Ratchet for {recipient_id} with our DH public key {our_dh_public} and their DH public key {their_dh_public}")

        # Ensure shared_secret is bytes-like
        if not isinstance(shared_secret, bytes):
            print(f":initiate_double_ratchet: Shared secret must be bytes, but it is {type(shared_secret)}")
            print(f":initiate_double_ratchet: Shared secret: {shared_secret}")
            return

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
        print(f"Derived keys for {recipient_id} - RK: {rk.hex()}, CKs: {cks.hex()}, CKr: {ckr.hex()}")

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

    def initiate_double_ratchet_received(self, recipient_id, shared_secret, our_dh_public, their_dh_public):
        print(
            f"{self.name} is Initializing Double Ratchet for {recipient_id} with our DH public key {our_dh_public} and their DH public key {their_dh_public}")

        # Ensure shared_secret is bytes-like
        if not isinstance(shared_secret, bytes):
            print(f":initiate_double_ratchet: Shared secret must be bytes, but it is {type(shared_secret)}")
            print(f":initiate_double_ratchet: Shared secret: {shared_secret}")
            return

        kdf = HKDF(
            algorithm=hashes.SHA256(),  # Note the parentheses to instantiate SHA256
            length=96,  # Adjust length based on your needs
            salt=None,  # Typically, the salt can be None if not using one
            info=b'init double ratchet',  # This can be application specific information
            backend=default_backend()
        )

        key_material = kdf.derive(shared_secret)

        # Split the derived key material into the root key (RK), and two chain keys (CKs, CKr)
        rk, ckr, cks = key_material[:32], key_material[32:64], key_material[64:]
        print(f"Derived keys for {recipient_id} - RK: {rk.hex()}, CKs: {cks.hex()}, CKr: {ckr.hex()}")

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

        print(f"Performing ratchet step with {recipient_id}. their_dh_public: {their_dh_public}")

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

    def decrypt_skipped_message(self, sender_id, message_number, ciphertext, nonce):
        # Check for existence of skipped messages for this sender
        if sender_id not in self.ratchet_states or 'MKSKIPPED' not in self.ratchet_states[sender_id]:
            print(f"No skipped messages for {sender_id}")
            return None

        their_dh_public = self.ratchet_states[sender_id]['DHr']

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

    def decrypt_with_chain_key(self, sender_id, message_number, ciphertext_base64, nonce_base64):
        if sender_id not in self.ratchet_states:
            raise ValueError(f"No ratchet state for sender {sender_id}")

        nonce = base64.b64decode(nonce_base64)
        ciphertext = base64.b64decode(ciphertext_base64)

        print(
            f"{self.name} is trying to decrypt message from {sender_id}, ciphertext: {ciphertext} nonce: {nonce}")

        if 'CKr' not in self.ratchet_states[sender_id] or 'Nr' not in self.ratchet_states[sender_id]:
            print(f"Receiving chain key or message number not initialized for {sender_id}.")
            return None

        current_message_number = self.ratchet_states[sender_id]['Nr']


        if message_number != current_message_number:
            print(
                f"Message number {message_number} does not match expected number {current_message_number}. Attempting to decrypt with skipped key.")
            return self.decrypt_skipped_message(sender_id,  message_number, ciphertext, nonce)

        # Use the current receiving chain key for decryption
        chain_key = self.ratchet_states[sender_id]['CKr']
        message_key, new_chain_key = self.derive_message_key(chain_key)

        print(
            f"Trying  , derived keys using chain key: {chain_key} = message_key:{message_key} , new_chain_key:{new_chain_key}")
        print(
            f"Ciphertext: {ciphertext} nonce:{nonce}")

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

        # Ensure we're working with the sending chain
        if 'CKs' not in self.ratchet_states[recipient_id]:
            print(f"Missing sending chain key for recipient {recipient_id}.")
            return None

        print(f"{self.name} is encrypting a message for {recipient_id}, plaintext: {plaintext}" )

        chain_key = self.ratchet_states[recipient_id]['CKs']
        message_key, new_chain_key = self.derive_message_key(chain_key)  # Derive message key from chain key

        aesgcm = AESGCM(message_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

        message_number = self.ratchet_states[recipient_id]['Ns']

        # update chain keys
        self.ratchet_states[recipient_id]['CKs'] = new_chain_key
        self.ratchet_states[recipient_id]['Ns'] += 1

        print(f"encrypted!!! Used AESGCM , derived keys using chain key: {chain_key} = message_key:{message_key} , new_chain_key:{new_chain_key}")
        print(
            f"Ciphertext: {ciphertext} nonce:{nonce}")

        return ciphertext, nonce, message_number

    # def update_receiving_chain_key(self, sender_id):
    #     # Update the receiving chain key (CKr) using KDF and increment Nr
    #     chain_key = self.ratchet_states[sender_id]['CKr']
    #     new_chain_key = self.derive_ratchet_key(chain_key)
    #     self.ratchet_states[sender_id]['CKr'] = new_chain_key
    #     self.ratchet_states[sender_id]['Nr'] += 1
    #
    # def update_sending_chain_key(self, sender_id):
    #     # Update the receiving chain key (CKr) using KDF and increment Nr
    #     chain_key = self.ratchet_states[sender_id]['CKs']
    #     new_chain_key = self.derive_ratchet_key(chain_key)
    #     self.ratchet_states[sender_id]['CKs'] = new_chain_key
    #     self.ratchet_states[sender_id]['Ns'] += 1

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