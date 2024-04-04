# from User import User
# from flask import Flask, jsonify
#
# app = Flask(__name__)
#
#
# user = User(name="User1", server_url="http://127.0.0.1:5020", dh_utils=dh_utils, max_one_time_prekeys=5)
#
# @app.route('/rekey', methods=['POST'])
# def handle_rekey_request():
#     print("Received rekey request.")
#     user.generate_and_upload_new_prekeys()
#     return jsonify({'message': 'New one-time prekeys generated and uploaded.'}), 200
#
# if __name__ == "__main__":
#     app.run(debug=True, port=5001)