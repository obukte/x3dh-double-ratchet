from src.User import User
# from src.dh_utils import DiffieHellmanUtils
import time
from src.DiffieHellmanUtils import DiffieHellmanUtils


# Mock server run

dh_utils = DiffieHellmanUtils

# Initialize two users
alice = User("Alice", "http://127.0.0.1:5020", max_one_time_prekeys=50)
bob = User("Bob", "http://127.0.0.1:5020", max_one_time_prekeys=50)

time.sleep(5)

# Simulate Alice sending a message to Bob
alice.send_message("Bob", "Hello Bob, this is Alice!")

time.sleep(3)

# Simulate fetching messages for Bob from the server
bob.fetch_messages()

time.sleep(3)

# Simulate Bob sending a reply to Alice
bob.send_message("Alice", "Hello Alice, I received your message!")

time.sleep(3)

alice.fetch_messages()

# Simulate Bob sending a reply to Alice
bob.send_message("Alice", "Hello Alice, new message!")

time.sleep(3)

# Simulate Bob sending a reply to Alice
bob.send_message("Alice", "Hello Alice, new message  2!")

time.sleep(3)

# Simulate fetching messages for Alice from the server
alice.fetch_messages()

time.sleep(3)

# Sending more messages
alice.send_message("Bob", "Hello Bob, new message 2!")
alice.send_message("Bob", "Hello Bob, new message 3!")
alice.send_message("Bob", "Hello Bob, new message 4!")
alice.send_message("Bob", "Hello Bob, new message 5!")
alice.send_message("Bob", "Hello Bob, new message 6!")
alice.send_message("Bob", "Hello Bob, new message 7!")
alice.send_message("Bob", "Hello Bob, new message 8!")
alice.send_message("Bob", "Hello Bob, new message 9!")
alice.send_message("Bob", "Hello Bob, new message 10!")
alice.send_message("Bob", "Hello Bob, new message 11!")
alice.send_message("Bob", "Hello Bob, new message 12!")
alice.send_message("Bob", "Hello Bob, new message 13!")
time.sleep(3)

bob.fetch_messages()

time.sleep(5)

bob.send_message("Alice", "Hello Alice, new message  3!")
bob.send_message("Alice", "Hello Alice, new message  4!")
bob.send_message("Alice", "Hello Alice, new message  3!")
bob.send_message("Alice", "Hello Alice, new message  4!")

time.sleep(3)

bob.send_message("Alice", "Hello Alice, new message  5!")
bob.send_message("Alice", "Hello Alice, new message  6!")
bob.send_message("Alice", "Hello Alice, new message  7!")


time.sleep(5)

alice.send_message("Bob", "Hello Bob, new message 14!")
alice.send_message("Bob", "Hello Bob, new message 15!")
alice.fetch_messages()

alice.send_message("Bob", "Hello Bob, new message 16!")
alice.send_message("Bob", "Hello Bob, new message 17!")
alice.send_message("Bob", "Hello Bob, new message 18!")
alice.send_message("Bob", "Hello Bob, new message 19!")
alice.send_message("Bob", "Hello Bob, new message 20!")
alice.send_message("Bob", "Hello Bob, new message 21!")
alice.send_message("Bob", "Hello Bob, new message 22!")

alice.fetch_messages()

# Wait a moment to allow asynchronous actions to complete
time.sleep(3)

bob.fetch_messages()
