#!/usr/bin/env python
# coding: utf-8

from flask import Flask, request, jsonify
from diffiehellman_utils.diffie_hellman_utils import DiffieHellmanUtils

app = Flask(__name__)

users = {}
messages = {}

dh_utils = DiffieHellmanUtils()
dh_parameters = {'prime': None, 'generator': None}
prime, generator = dh_utils.generate_base_and_prime()


@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    user_id = data.get('user_id')
    identity_key = int(data['public_key']['identity_key'])
    signed_prekey = int(data['public_key']['signed_prekey'])
    one_time_prekeys = [int(pk) for pk in data['public_key']['one_time_prekeys']]  # Expecting a list of one-time prekeys

    if not user_id or not identity_key or not signed_prekey or not one_time_prekeys:
        return jsonify({'error': 'All key material is required'}), 400

    if user_id in users:
        return jsonify({'error': 'User ID already registered'}), 409

    # Store the user's X3DH key material
    users[user_id] = {
        'identity_key': identity_key,
        'signed_prekey': signed_prekey,
        'one_time_prekeys': one_time_prekeys,
    }

    return jsonify({'success': True, 'message': f'User {user_id} registered successfully'}), 201

@app.route('/get_keys/<user_id>', methods=['GET'])
def get_keys(user_id):
    if user_id not in users:
        return jsonify({'error': 'User does not exist'}), 404

    # Fetch and return the user's public key material necessary for X3DH
    user_keys = users.get(user_id)
    if user_keys and user_keys['one_time_prekeys']:
        one_time_prekey = user_keys['one_time_prekeys'].pop(0)

        if not user_keys['one_time_prekeys']:
            print(f"User {user_id}'s one-time prekeys are depleted. Requesting new prekeys.")
            request_rekey(user_id)

        return jsonify({
            'identity_key': user_keys['identity_key'],
            'signed_prekey': user_keys['signed_prekey'],
            'one_time_prekey': one_time_prekey,
        }), 200
    else:
        return jsonify({'error': f'No one-time prekeys left for {user_id}'}), 400

@app.route('/request_rekey/<user_id>', methods=['POST'])
def request_rekey(user_id):

    if user_id not in users:
        return jsonify({'error': 'User does not exist'}), 404


    return jsonify({'success': True, 'message': f'Rekey request sent to {user_id}'}), 200

@app.route('/update_prekeys', method=['POST'])
def update_prekeys():
    data = request.json
    user_id = data.get('user_id')
    new_one_time_prekeys = data['public_key'].get('one_time_prekeys', [])

    if not user_id or user_id not in users:
        return jsonify({'error': 'Invalid or missing user ID'}),
    if not new_one_time_prekeys:
        return jsonify({'error': 'No new one-time prekeys provided'}), 400

    users[user_id]['one_time_prekeys'] = new_one_time_prekeys

    return  jsonify({'success': True, 'message': f'One-time prekey updated for user {user_id}'}), 200



@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    recipient_id = data.get('recipient_id')
    sender_id = data.get('sender_id')
    encrypted_message = data.get('encrypted_message')
    nonce = data.get('nonce')
    new_dh_public_key = data.get('new_dh_public_key', None)

    if recipient_id not in messages:
        messages[recipient_id] = []

    message_data = {
        'sender_id': sender_id,
        'encrypted_message': encrypted_message,
        'nonce': nonce,
    }
    if new_dh_public_key:
        message_data['new_dh_public_key'] = new_dh_public_key

    messages[recipient_id].append(message_data)

    if not sender_id:
        return jsonify({'error': 'Sender ID is missing'}), 400
    if not recipient_id:
        return jsonify({'error': 'Recipient ID is missing'}), 400
    if not encrypted_message:
        return jsonify({'error': 'Encrypted message is missing'}), 400
    if recipient_id not in users:
        return jsonify({'error': 'Recipient does not exist'}), 404

    return jsonify({'success': True, 'message': 'Message sent successfully'}), 200


@app.route('/fetch_messages/<user_id>', methods=['GET'])
def fetch_messages(user_id):
    # Fetch messages intended for the user
    user_messages = messages.get(user_id, [])
    # Prepare response before deleting or marking as delivered
    response = jsonify({'messages': user_messages})

    # Option 1: Delete messages after fetching
    if user_id in messages:
        del messages[user_id]

    # Option 2: Mark messages as delivered (not shown here, would require message status tracking)

    return response, 200

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

# @app.route('/update_keys/<recipient_id>', methods=['POST'])
# def update_keys(recipient_id):
#     if recipient_id not in users:
#         return jsonify({'error': 'User does not exist'}), 404
#
#     data = request.json
#     sender_id = data.get('sender_id')
#     new_dh_public_key = data.get('new_dh_public_key')
#     if recipient_id not in ratchet_keys:
#         ratchet_keys[recipient_id] = {}
#
#     ratchet_keys[recipient_id][sender_id] = new_dh_public_key
#     return jsonify({'success': True, 'message': 'Ratchet public key updated sucessfully'}), 200
#
# @app.route('/get_keys_with_ratchet/<recipient_id>/<sender_id>', methods=['GET'])
# def get_keys_with_ratchet(recipient_id, sender_id):
#     if recipient_id not in users:
#         return jsonify({'error': 'Recipient does not exist'}), 404
#
#     if recipient_id not in ratchet_keys or sender_id not in ratchet_keys[recipient_id]:
#         return jsonify({'error': 'No ratchet key available for this sender and recipient pair'}), 404
#
#     new_dh_public_key = ratchet_keys[recipient_id][sender_id]
#     return jsonify({'new_dh_public_key': new_dh_public_key}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5020)