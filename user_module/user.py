#!/usr/bin/env python
# coding: utf-8

import os
import requests
import cryptography.exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from diffiehellman_utils.diffie_hellman_utils import DiffieHellmanUtils

dh_utils = DiffieHellmanUtils()
name = "User1"
server_url = "http://127.0.0.1:5020"
DH_RATCHET_UPDATE_THRESHOLD = 2


class User():

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

    def sign_prekey(self, identity_private_key, signed_prekey_public):

        prekey_public_bytes = signed_prekey_public.to_bytes((signed_prekey_public.bit_lenght() + 7) // 8, byteorder='big')

        hash_digest = hashes.Hash(hashes.SHA256())
        hash_digest.update(prekey_public_bytes)
        hashed_prekey = hash_digest.finalize()

        simulated_signature = pow(int.from_bytes(hashed_prekey, byteorder='big'), identity_private_key, self.prime)
        return simulated_signature.to_bytes((simulated_signature.bit_length() + 7) // 8, byteorder='big')

    def verify_signature(self, signing_public_key, prekey_public, signature):
        # Convert the prekey_public to bytes for hashing
        prekey_public_bytes = prekey_public.to_bytes((prekey_public.bit_length() + 7) // 8, byteorder='big')

        # Hash the public prekey
        hash_digest = hashes.Hash(hashes.SHA256())
        hash_digest.update(prekey_public_bytes)
        hashed_prekey = hash_digest.finalize()

        # Simulate "decryption" with the public key
        decrypted_hash_int = pow(int.from_bytes(signature, byteorder='big'), signing_public_key, self.prime)
        decrypted_hash = decrypted_hash_int.to_bytes((decrypted_hash_int.bit_length() + 7) // 8, byteorder='big')

        # Compare the hashes to verify the signature
        return decrypted_hash == hashed_prekey

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

    def fetch_public_keys(self, user_id):
        url = f'{self.server_url}/get_keys/{user_id}'
        response = requests.get(url)
        if response.status_code == 200:
            public_keys = response.json()

            return {
                'identity_key': public_keys['identity_key'],
                'signed_prekey': public_keys['signed_prekey'],
                'one_time_prekeys': public_keys['one_time_prekeys']
            }
        else:
            print(f"Failed to fetch keys for {user_id}")
            return None

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
        if recipient_keys in None:
            print("Failed to fetch recipient's keys.")

        shared_secret, ephemeral_public_key = self.perform_x3dh_key_agreement(recipient_id, recipient_keys)

        # Check if it's time to perform a DH ratchet step
        if self.should_update_dh_ratchet(recipient_id):
            new_private_key, new_public_key = self.dh_utils.generate_key_pair(self.generator, self.prime)
            new_dh_public_key_hex = hex(new_public_key)[2:]

            recipient_keys = self.fetch_public_keys(recipient_id)
            recipient_identity_key = recipient_keys['identity_key']
            if isinstance(recipient_identity_key, str):
                recipient_identity_key = int(recipient_identity_key, 16)  # Convert from hex string to int
            elif not isinstance(recipient_identity_key, int):
                print(f"Error: recipient_identity_key is of unexpected type: {type(recipient_identity_key)}")
                return

            new_shared_secret = self.dh_utils.calculate_shared_secret(self.prime, new_private_key, recipient_identity_key)

            new_root_key, new_sending_chain_key, new_receiving_chain_key = self.derive_new_keys_from_shared_secret(new_shared_secret)

            self.ratchet_states[recipient_id] = {
                'RK': new_root_key,
                'sending_chain_key': new_sending_chain_key,
                'receiving_chain_key': new_receiving_chain_key,
                'new_dh_private_key': new_private_key,
                'new_dh_public_key': new_public_key,
                'Ns': 0,
                'Nr': 0,
            }

        if recipient_id not in self.shared_secrets or recipient_id not in self.ratchet_states:
            recipient_keys = self.fetch_public_keys(recipient_id)
            shared_secret = self.perform_x3dh_key_agreement(recipient_id, recipient_keys)
            self.shared_secrets[recipient_id] = shared_secret
            if recipient_id not in self.ratchet_states:
                self.initialize_ratchet_for_recipient(recipient_id, shared_secret)

        recipient_id, nonce, encrypted_message = self.encrypt_message(recipient_id, message)
        data = {
            'sender_id': self.name,
            'recipient_id': recipient_id,
            'encrypted_message': encrypted_message.hex(),
            'nonce': nonce.hex(),
            'new_dh_public_key': new_dh_public_key_hex
        }
        # Filter out None values
        data = {k: v for k, v in data.items() if v is not None}

        response = requests.post(f'{self.server_url}/send_message', json=data)
        if response.status_code == 200:
            print("Message sent successfully.")
        else:
            print("Failed to send message:", response.json())

    def perform_x3dh_key_agreement(self, recipient_id, recipient_keys):

        ephemeral_private_key, ephemeral_public_key = self.dh_utils.generate_key_pair(self.generator, self.prime)

        DH1 = self.dh_utils.calculate_shared_secret(self.prime, self.identity_private, recipient_keys['signed_prekey'])
        DH2 = self.dh_utils.calculate_shared_secret(self.prime, self.signed_prekey_private, recipient_keys['identity_key'])
        DH3 = self.dh_utils.calculate_shared_secret(self.prime, self.one_time_prekey_private[0],
                                                    recipient_keys['signed_prekey'])
        DH4 = self.dh_utils.calculate_shared_secret(self.prime, self.identity_private,
                                                    recipient_keys.get('one_time_prekey', 0))

        # Combine the DH secrets to derive the shared secret
        shared_secret = self.dh_utils.combine_secrets(DH1, DH2, DH3, DH4)

        self.shared_secrets[recipient_id] = shared_secret
        self.initialize_ratchet_for_recipient(recipient_id, shared_secret)

        return shared_secret

    def initialize_ratchet_for_recipient(self, recipient_id, shared_secret, recipient_dh_public_key=None):
        if recipient_id not in self.ratchet_states:
            self.ratchet_states[recipient_id] = {}

        our_new_ratchet_private_key, our_new_ratchet_public_key = self.dh_utils.generate_key_pair(self.generator, self.prime)

        shared_secret = self.dh_utils.calculate_shared_secret(self.prime, recipient_dh_public_key, )

        if 'DHRr' in self.ratchet_states[recipient_id] and self.ratchet_states[recipient_id]['DHRr'] is not None:
            new_dh_secret = self.dh_utils.calculate_shared_secret(
                self.prime,
                self.ratchet_states[recipient_id]['DHRr'],
                self.ratchet_states[recipient_id]['DHRs_private']
            )
            combined_secret = self.dh_utils.combine_secrets(shared_secret, new_dh_secret)
        else:
            combined_secret = shared_secret

        self.ratchet_states[recipient_id]['RK'] = self.dh_utils.kdf(combined_secret)
        self.ratchet_states[recipient_id]['CKs'] = self.dh_utils.kdf(combined_secret)

        self.ratchet_states[recipient_id]['Ns'] = 0
        self.ratchet_states[recipient_id]['Nr'] = 0
        self.ratchet_states[recipient_id]['PN'] = 0
        self.ratchet_states[recipient_id]['MKSKIPPED'] = {}

        shared_hka, shared_nhkb = self.generate_header_keys(shared_secret)
        self.ratchet_states[recipient_id]['HKs'] = shared_hka
        self.ratchet_states[recipient_id]['NHKs'] = shared_nhkb

    def update_chain(self, chain_key):
        new_chain_key = dh_utils.kdf(chain_key)
        message_key = dh_utils.kdf(chain_key)
        return new_chain_key, message_key

    def derive_message_key(self, chain_keys):
        message_key = dh_utils.kdf(chain_keys)
        new_chain_key = dh_utils.kdf(chain_keys)
        return message_key, new_chain_key

    def encrypt_message(self, recipient_id, plaintext):
        if recipient_id not in self.ratchet_states:
            raise ValueError(f"No ratchet state for recipient {recipient_id}")

        sending_chain_key = self.ratchet_states[recipient_id]['sending_chain_key']
        message_key, new_sending_chain_key = self.update_chain(sending_chain_key)

        aesgcm = AESGCM(message_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

        self.ratchet_states[recipient_id]['sending_chain_key'] = new_sending_chain_key
        self.ratchet_states[recipient_id]['Ns'] += 1

        return recipient_id, nonce, ciphertext

    def decrypt_message(self, sender_id, nonce, ciphertext):
        if sender_id not in self.ratchet_states:
            raise ValueError(f"No ratchet state for sender {sender_id}")

        receiving_chain_key = self.ratchet_states[sender_id]['receiving_chain_key']
        message_key, new_receiving_chain_key = self.update_chain(receiving_chain_key)

        aesgcm = AESGCM(message_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            self.ratchet_states[sender_id]['receiving_chain_key'] = new_receiving_chain_key
            self.ratchet_states[sender_id]['Ns'] += 1
            return plaintext.decode()
        except cryptography.exceptions.InvalidKey as e:
            print(f"Decryption failed due to an Invalid tag : {str(e)}")
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
        return None

    def fetch_messages(self):
        response = requests.get(f'{self.server_url}/fetch_messages/{self.name}')
        if response.status_code == 200:
            messages = response.json().get('messages', [])
            for msg in messages:
                sender_id = msg['sender_id']

                if sender_id not in self.shared_secrets:
                    sender_keys = self.fetch_public_keys(sender_id)
                    shared_secret = self.perform_x3dh_key_agreement(sender_id, sender_keys)
                    self.shared_secrets[sender_id] = shared_secret

                if sender_id not in self.ratchet_states:
                    self.initialize_ratchet_for_recipient(sender_id, shared_secret)

                if 'new_dh_public_key' in msg:
                    new_dh_public_key = msg['new_dh_public_key']
                    self.handle_new_dh_public_key(sender_id, new_dh_public_key)

                encrypted_message = bytes.fromhex(msg['encrypted_message'])
                nonce = bytes.fromhex(msg['nonce'])

                try:
                    decrypted_message = self.decrypt_message(sender_id, nonce, encrypted_message)
                    print(f"From {sender_id}: {decrypted_message}")
                except cryptography.exceptions.InvalidKey:
                    print(f"Failed to decrypt message from {sender_id}: Invalid tag")
                except Exception as e:
                    print(f"Decryption failed: {e}")
        else:
            print("Failed to fetch messages:", response.json())

    def handle_new_dh_public_key(self, sender_id, new_dh_public_key_hex):

        if sender_id not in self.ratchet_states or 'new_dh_private_key' not in self.ratchet_states[sender_id]:
            print(f"Error: Missing ratchet state or new DH private key for {sender_id}.")
            return

        new_dh_public_key = int(new_dh_public_key_hex, 16)
        new_shared_secret = self.dh_utils.calculate_shared_secret(self.prime, int(new_dh_public_key), self.ratchet_states[sender_id]['new_dh_private_key'])

        new_root_key, new_sending_chain_key, new_receiving_chain_key = self.derive_new_keys_from_shared_secret(new_shared_secret)

        self.ratchet_states[sender_id].update({
            'RK': new_root_key,
            'sending_chain_key': new_sending_chain_key,
            'receiving_chain_key': new_receiving_chain_key,
            'Ns': 0,
            'Nr': 0,
        })
        print(f"Updated ratchet state for {sender_id}:")
        print(f"  New RK: {new_root_key.hex()}")
        print(f"  New Sending Chain Key: {new_sending_chain_key.hex()}")
        print(f"  New Receiving Chain Key: {new_receiving_chain_key.hex()}")

    def derive_new_keys_from_shared_secret(self, shared_secret):
        new_root_key = self.dh_utils.kdf(shared_secret)
        new_sending_chain_key = self.dh_utils.kdf(new_root_key)
        new_receiving_chain_key = self.dh_utils.kdf(new_root_key)
        return new_root_key, new_sending_chain_key, new_receiving_chain_key

    def should_update_dh_ratchet(self, recipient_id):
        if recipient_id in self.ratchet_states and 'Ns' in self.ratchet_states[recipient_id]:
            if self.ratchet_states[recipient_id]['Ns'] >= DH_RATCHET_UPDATE_THRESHOLD:
                return True

        return False
