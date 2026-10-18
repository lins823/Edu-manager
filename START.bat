@echo off
cd /d "%~dp0"
echo Installing requirements (first time only)...
python -m pip install -r requirements.txt >nul 2>nul || py -m pip install -r requirements.txt >nul 2>nul
echo Starting Excellence Academy SMS on http://localhost:5000
python app.py || py app.py
pause
