======================================================
  URL Phishing Detector — Setup & Run Instructions
======================================================

REQUIREMENTS
------------
- Windows, Mac, or Linux computer
- Python 3.12  (download from https://www.python.org/downloads/)
- At least 2 GB of free disk space for the packages


STEP 1 — Install Python 3.12
-----------------------------
1. Go to https://www.python.org/downloads/
2. Download Python 3.12.x (the "Windows installer 64-bit")
3. Run the installer
4. IMPORTANT: tick "Add Python to PATH" before clicking Install


STEP 2 — Open a terminal in this folder
----------------------------------------
1. Open File Explorer and navigate to this folder
2. Click the address bar at the top, type "cmd", press Enter
   (This opens a Command Prompt already in this folder)


STEP 3 — Create a virtual environment
---------------------------------------
In the Command Prompt, type these commands one at a time:

    py -3.12 -m venv venv

Then activate it:
  Windows:  venv\Scripts\activate
  Mac/Linux: source venv/bin/activate

You will see (venv) appear at the start of the line.


STEP 4 — Install packages
---------------------------
    pip install -r requirements.txt

This takes a few minutes. Wait for it to finish.


STEP 5 — Run the app
----------------------
    streamlit run app/prototype.py

Your browser will open automatically at http://localhost:8501


STEP 6 — Use the app
----------------------
1. Paste any URL into the text box
2. Click "Check URL"
3. See the result: HIGH RISK or LOW RISK, with an explanation

To stop the app: press Ctrl+C in the terminal


TROUBLESHOOTING
---------------
- If "py -3.12" is not recognised, try "python" instead
- If the browser does not open automatically, go to http://localhost:8501 manually
- If you see any red error about a missing model file, make sure the "models"
  folder is present and contains "xgboost.joblib"


FILES INCLUDED
--------------
  app/prototype.py             - the web app
  src/feature_extractor.py     - extracts features from a URL
  src/prepare_data.py          - data cleaning pipeline
  src/train.py                 - model training script
  src/explain.py               - SHAP + LIME explainability
  models/xgboost.joblib        - the trained phishing detection model
  requirements.txt             - list of Python packages needed
