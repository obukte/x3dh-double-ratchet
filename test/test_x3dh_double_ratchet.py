from src.User import User
from src.dh_utils import DiffieHellmanUtils
import time


# Mock server run

dh_utils = DiffieHellmanUtils()

# Initialize two users
alice = User("Alice", "http://127.0.0.1:5020", dh_utils, max_one_time_prekeys=5)
bob = User("Bob", "http://127.0.0.1:5020", dh_utils, max_one_time_prekeys=5)

time.sleep(1)

# Simulate Alice sending a message to Bob
alice.send_message("Bob", "Hello Bob, this is Alice!")

time.sleep(1)

# Simulate fetching messages for Bob from the server
bob.fetch_messages()

time.sleep(1)

# Simulate Bob sending a reply to Alice
bob.send_message("Alice", "Hello Alice, I received your message!")

time.sleep(1)

# Simulate Bob sending a reply to Alice
bob.send_message("Alice", "Hello Alice, new message!")

time.sleep(1)

# Simulate Bob sending a reply to Alice
bob.send_message("Alice", "Hello Alice, new message  2!")

time.sleep(1)

# Simulate fetching messages for Alice from the server
alice.fetch_messages()

time.sleep(1)

# Wait a moment to allow asynchronous actions to complete
time.sleep(2)
