@echo off
setlocal
cd /d "%~dp0"

if exist "venv\Scripts\python.exe" (
  set "PY=venv\Scripts\python.exe"
) else if exist ".venv\Scripts\python.exe" (
  set "PY=.venv\Scripts\python.exe"
) else (
  set "PY=python"
)

echo Starting monitoring worker using %PY%
"%PY%" monitoring_worker.py

endlocal
