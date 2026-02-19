@echo off
echo ================================================
echo   GovVerify AI - Backend Server Startup
echo   AI-powered Government Notice Verification
echo ================================================
echo.

cd /d "%~dp0backend"

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt --quiet

echo.
echo ================================================
echo   Starting GovVerify AI Backend Server...
echo   API will be available at http://localhost:5000
echo ================================================
echo.
echo Press Ctrl+C to stop the server
echo.

REM Start the Flask server
python app.py
