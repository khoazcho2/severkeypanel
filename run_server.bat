@echo off
cd /d "%~dp0"
python.exe -m pip install -r requirements.txt
python.exe server.py
pause
