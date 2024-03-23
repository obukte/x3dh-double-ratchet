#!/bin/bash

cd /Users/macbook/Documents/Development/x3dh-double-ratchet

# Activate the virtual environment
source venv/bin/activate

# Start the relay server
python server_module/relay_server.py &

# Run your Python test script
python test/test_x3dh_double_ratchet.py

# Kill the server after the test script finishes
kill $(pgrep -f "python server_module/relay_server.py")
