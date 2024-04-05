#!/usr/bin/env python
# coding: utf-8
import base64

from flask import Flask, request, jsonify
from DiffieHellmanUtils import DiffieHellmanUtils

app = Flask(__name__)

users = {}
messages = {}

dh_utils = DiffieHellmanUtils()
dh_parameters = {'prime': None, 'generator': None}
prime, generator = dh_utils.generate_base_and_prime()
dh_parameters['prime'], dh_parameters['generator'] = prime, generator

ONE_TIME_KEY_COUNT = 10


@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    user_id = data.get('user_id')

    if user_id in users:
        return jsonify({'error': 'User ID already registered'}), 409

    try:
        identity_key_base64 = data['public_key']['identity_key']
        signed_prekey_base64 = data['public_key']['signed_prekey']
        one_time_prekeys_base64_list = data['public_key']['one_time_prekeys']  # Expecting a list of one-time prekeys

        if not user_id or not identity_key_base64 or not signed_prekey_base64 or not one_time_prekeys_base64_list:
            return jsonify({'error': 'All key material is required'}), 400


        # Store the user's X3DH key material
        users[user_id] = {
            'identity_key': identity_key_base64,
            'signed_prekey': signed_prekey_base64,
            'one_time_prekeys': one_time_prekeys_base64_list,
        }

        return jsonify({'success': True, 'message': f'User {user_id} registered successfully'}), 201

    except Exception as e:
        return jsonify({'error': 'Registration failed due to an error'}), 500

@app.route('/get_keys/<user_id>', methods=['GET'])
def get_keys(user_id):
    if user_id not in users:
        return jsonify({'error': 'User does not exist'}), 404

    user_keys = users.get(user_id)
    if user_keys and user_keys['one_time_prekeys']:
        # Determine the number of one-time prekeys to distribute
        keys_to_send = min(ONE_TIME_KEY_COUNT, len(user_keys['one_time_prekeys']))

        # Fetch the specified number of one-time prekeys for the requesting user
        one_time_prekeys_to_send = user_keys['one_time_prekeys'][:keys_to_send]

        # Remove the distributed one-time prekeys from the user's store
        del user_keys['one_time_prekeys'][:keys_to_send]

        # Check if one-time prekeys are running low and notify the user to regenerate
        if len(user_keys['one_time_prekeys']) < ONE_TIME_KEY_COUNT:
            print(f"User {user_id}'s one-time prekeys are running low. Notifying user to regenerate.")
            # Add logic here to notify the user to regenerate one-time prekeys

        return jsonify({
            'identity_key': user_keys['identity_key'],
            'signed_prekey': user_keys['signed_prekey'],
            'one_time_prekey': one_time_prekeys_to_send,
            'rekey_needed': len(user_keys['one_time_prekeys']) < ONE_TIME_KEY_COUNT  # Indicate if rekeying is needed
        }), 200
    else:
        return jsonify({'error': f'No one-time prekeys left for {user_id}. Please regenerate.'}), 400



# @app.route('/request_rekey/<user_id>', methods=['POST'])
# def request_rekey(user_id):
#
#     if user_id not in users:
#         return jsonify({'error': 'User does not exist'}), 404
#
#
#     return jsonify({'success': True, 'message': f'Rekey request sent to {user_id}'}), 200

@app.route('/update_prekeys', methods=['POST'])
def update_prekeys():
    data = request.json
    user_id = data.get('user_id')
    new_one_time_prekeys = data.get('one_time_prekeys')


    if not user_id or user_id not in users:
        return jsonify({'error': 'Invalid or missing user ID'}),
    if not new_one_time_prekeys:
        return jsonify({'error': 'No new one-time prekeys provided'}), 400

    users[user_id]['one_time_prekeys'].extend(new_one_time_prekeys)

    return  jsonify({'success': True, 'message': f'One-time prekey updated for user {user_id}'}), 200



@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    recipient_id = data.get('recipient_id')
    sender_id = data.get('sender_id')
    encrypted_message = data.get('encrypted_message')
    nonce = data.get('nonce')
    message_number = data.get('message_number')

    # This may be included in the first message of a conversation or when a ratchet step occurs
    new_dh_public_key = data.get('new_dh_public_key', None)
    initial_package = data.get('initial_package', None)

    if not sender_id or not recipient_id or not encrypted_message or message_number is None:
        return jsonify({'error': 'Missing necessary information'}), 400

    if recipient_id not in users:
        return jsonify({'error': 'Recipient does not exist'}), 404

    # Prepare message data for the recipient, including any initial X3DH or ratchet step information
    message_data = {
        'sender_id': sender_id,
        'encrypted_message': encrypted_message,
        'nonce': nonce,
        'message_number': message_number
    }

    if new_dh_public_key:
        message_data['new_dh_public_key'] = new_dh_public_key

    if initial_package:
        # Include initial X3DH package information if present
        message_data['initial_package'] = initial_package

    messages.setdefault(recipient_id, []).append(message_data)

    return jsonify({'success': True, 'message': 'Message sent successfully'}), 200

@app.route('/fetch_messages/<user_id>', methods=['GET'])
def fetch_messages(user_id):
    # Ensure the user exists
    if user_id not in users:
        return jsonify({'error': 'User not found'}), 404

    # Fetch messages intended for the user
    user_messages = messages.get(user_id, [])

    # Prepare messages to be fetched before marking them as delivered
    response_messages = []
    for msg in user_messages:
        response_messages.append(msg)

    # Delete the messages after fetching.
    if user_id in messages:
        del messages[user_id]

    return jsonify({'messages': response_messages}), 200


@app.route('/acknowledge_message', methods=['POST'])
def acknowledge_message():
    data = request.json
    recipient_id = data.get('recipient_id')
    message_id = data.get('message_id')
    if recipient_id in messages and message_id < len(messages[recipient_id]):
        del messages[recipient_id][message_id]  # Delete the acknowledged message
        return jsonify({'success': True, 'message': 'Message acknowledged'}), 200
    return jsonify({'error': 'Message or recipient not found'}), 404

@app.route('/dh_parameters', methods=['GET'])
def get_dh_parameters():
    dh_parameters['prime'] = prime
    dh_parameters['generator'] = generator
    return jsonify(dh_parameters), 200

if __name__ == '__main__':
    app.run(debug=True, port=5020)