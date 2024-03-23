from server_module import relay_server
from diffiehellman_utils import dh_utils
from user_module import User
import threading
import time


# Mock server run
def run_mock_server():
    relay_server.run(port=5020)


# Start the mock server in a separate thread
server_thread = threading.Thread(target=run_mock_server, daemon=True)
server_thread.start()

# Give the server a moment to start up
time.sleep(1)

# Initialize two users
alice = User("Alice", "http://127.0.0.1:5020", dh_utils, max_one_time_prekeys=5)
bob = User("Bob", "http://127.0.0.1:5020", dh_utils, max_one_time_prekeys=5)

# Simulate Alice sending a message to Bob
alice.send_message("Bob", "Hello Bob, this is Alice!")

# Simulate fetching messages for Bob from the server
bob.fetch_messages()

# Simulate Bob sending a reply to Alice
bob.send_message("Alice", "Hello Alice, I received your message!")

# Simulate fetching messages for Alice from the server
alice.fetch_messages()

# Wait a moment to allow asynchronous actions to complete
time.sleep(2)
