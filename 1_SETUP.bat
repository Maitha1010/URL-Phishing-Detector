@echo off
title Phishing Detector - First Time Setup
color 0A
echo ============================================
echo   Phishing URL Detector - Setup
echo ============================================
echo.
echo This will install the required packages.
echo No internet connection needed.
echo.

REM Check Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python 3.12 from python.org
    pause
    exit /b 1
)

echo Python found. Installing packages from local files...
echo This may take 2-3 minutes. Please wait.
echo.

REM Install from local wheels folder - no internet needed
python -m pip install --no-index --find-links="%~dp0wheels" -r "%~dp0requirements_app.txt" --quiet

if errorlevel 1 (
    echo.
    echo ERROR: Setup failed. Please contact support.
    pause
    exit /b 1
)

echo.
echo ============================================
echo   Setup complete!
echo   Now run  2_RUN_APP.bat  to start the app.
echo ============================================
echo.
pause
