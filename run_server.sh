#!/bin/bash

# Start the relay server
python relay_server.py &

# Run your Python test script
python test_x3dh_double_ratchet.py

# Kill the server after the test script finishes
kill $(pgrep -f "python relay_server.py")
