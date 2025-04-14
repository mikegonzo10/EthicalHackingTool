@echo off
echo Starting Ethical Hacking Toolkit...

REM Start the backend server
cd backend
call venv\Scripts\activate.bat
start /B python app.py

REM Wait for backend to initialize
timeout /t 3 /nobreak > nul

REM Open the frontend in the default browser
cd ..
start "" "http://localhost:5000"

echo Ethical Hacking Toolkit has been started! 