import time
import tkinter as tk
from tkinter import simpledialog, scrolledtext
import threading
from User import User


class UserApplication:
    def __init__(self, master):
        self.master = master
        master.title("X3DH Chat Application")

        self.label = tk.Label(master, text="Press 'Start' to create a user.")
        self.label.pack(pady=10)

        self.start_button = tk.Button(master, text="Start", command=self.on_start)
        self.start_button.pack(pady=10)

    def on_start(self):
        username = simpledialog.askstring("Input", "What is your username?")
        if username:
            self.user = User(username, "http://127.0.0.1:5020")
            print(self.user)  # For demonstration
            self.label.config(text=f"User: {self.user.name}")
            self.start_button.pack_forget()  # Hide the start button
            self.init_chat_ui()
            self.fetch_messages_thread = threading.Thread(target=self.fetch_messages)
            self.fetch_messages_thread.daemon = True
            self.fetch_messages_thread.start()

    def init_chat_ui(self):
        self.chat_label = tk.Label(self.master, text="Enter username to message:")
        self.chat_label.pack(pady=10)

        self.username_entry = tk.Entry(self.master)
        self.username_entry.pack(pady=10)

        self.start_chat_button = tk.Button(self.master, text="Start Chat", command=self.start_chat)
        self.start_chat_button.pack(pady=10)

    def start_chat(self):
        self.target_username = self.username_entry.get()
        if self.target_username:
            self.chat_label.pack_forget()
            self.username_entry.pack_forget()
            self.start_chat_button.pack_forget()

            # Display who you are chatting with
            self.chatting_with_label = tk.Label(self.master, text=f"Chatting with: {self.target_username}")
            self.chatting_with_label.pack(pady=10)

            self.messages_display = scrolledtext.ScrolledText(self.master, height=15, width=50)
            self.messages_display.pack(pady=10)
            self.messages_display.insert(tk.END, "Chat started\n")
            self.messages_display.config(state=tk.DISABLED)  # Make the display read-only

            self.message_entry = tk.Entry(self.master)
            self.message_entry.pack(pady=10)

            self.send_button = tk.Button(self.master, text="Send", command=self.send_message)
            self.send_button.pack(pady=10)

    def send_message(self):
        message = self.message_entry.get()
        if message:
            self.user.send_message(self.target_username, message)
            self.display_message(f"You: {message}")
            # Here you would add your logic to actually send the message using User methods
            self.message_entry.delete(0, tk.END)  # Clear the input field

    def fetch_messages(self):
        """Periodically fetch messages and update the chat display."""
        while True:
            # Assume the User class has a fetch_messages method returning [(sender_id, message), ...]
            messages = self.user.fetch_messages()
            for sender_id, message in messages:
                self.display_message(f"{sender_id}: {message}")
            time.sleep(2)  # Adjust as needed

    def display_message(self, message):
        if self.master.winfo_exists():  # Check if the window is still open
            self.messages_display.config(state=tk.NORMAL)  # Enable editing to insert a message
            self.messages_display.insert(tk.END, message + "\n")
            self.messages_display.config(state=tk.DISABLED)  # Disable editing again
            self.messages_display.see(tk.END)  # Scroll to the bottom


root = tk.Tk()
root.geometry("400x600")  # Make the window larger
app = UserApplication(root)
root.mainloop()
