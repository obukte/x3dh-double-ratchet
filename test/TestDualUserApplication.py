from multiprocessing import Process
import tkinter as tk
from src.UserApplication import UserApplication  # Adjust the import based on your script's structure

def run_app():
    root = tk.Tk()
    app = UserApplication(root)
    root.mainloop()

if __name__ == "__main__":
    # Number of GUI instances you want to run
    num_instances = 2

    processes = [Process(target=run_app) for _ in range(num_instances)]

    # Start all processes
    for p in processes:
        p.start()

    # Wait for all processes to complete
    for p in processes:
        p.join()
