@echo off
title Phishing URL Detector
color 0A
echo ============================================
echo   Phishing URL Detector
echo ============================================
echo.
echo Starting the app...
echo.
echo When you see "You can now view your Streamlit app",
echo open your browser and go to:
echo.
echo     http://localhost:8501
echo.
echo Keep this window open while using the app.
echo Close this window to stop the app.
echo.
echo ============================================
echo.

cd /d "%~dp0"
python -m streamlit run app/prototype.py --server.port 8501 --browser.gatherUsageStats false

if errorlevel 1 (
    echo.
    echo ERROR: Could not start the app.
    echo Make sure you ran 1_SETUP.bat first.
    pause
)
