from src.User import User
# from src.dh_utils import DiffieHellmanUtils
import time
from src.DiffieHellmanUtils import DiffieHellmanUtils


# Mock server run

dh_utils = DiffieHellmanUtils

# Initialize two users
alice = User("Alice", "http://127.0.0.1:5020", max_one_time_prekeys=5)
bob = User("Bob", "http://127.0.0.1:5020", max_one_time_prekeys=5)

time.sleep(10)

# Simulate Alice sending a message to Bob
alice.send_message("Bob", "Hello Bob, this is Alice!")

time.sleep(5)

# Simulate fetching messages for Bob from the server
bob.fetch_messages()

time.sleep(2)

# Simulate Bob sending a reply to Alice
bob.send_message("Alice", "Hello Alice, I received your message!")

time.sleep(2)

alice.fetch_messages()

# Simulate Bob sending a reply to Alice
bob.send_message("Alice", "Hello Alice, new message!")

time.sleep(2)

# Simulate Bob sending a reply to Alice
bob.send_message("Alice", "Hello Alice, new message  2!")

time.sleep(2)

# Simulate fetching messages for Alice from the server
alice.fetch_messages()

time.sleep(1)

# Wait a moment to allow asynchronous actions to complete
time.sleep(2)
