#!/bin/bash
echo "Starting Ethical Hacking Toolkit..."

# Start the backend server
cd backend
source venv/bin/activate
python app.py &

# Wait for backend to initialize
sleep 3

# Open the frontend in the default browser
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    open "http://localhost:5000"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    xdg-open "http://localhost:5000" &> /dev/null || firefox "http://localhost:5000" &> /dev/null || google-chrome "http://localhost:5000" &> /dev/null || echo "Please open http://localhost:5000 in your browser"
else
    echo "Please open http://localhost:5000 in your browser"
fi

echo "Ethical Hacking Toolkit has been started!" 