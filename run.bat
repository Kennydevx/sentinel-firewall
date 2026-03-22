@echo off
echo ============================================================
echo   Cryo-Corona Product Auto-Launcher
echo ============================================================
echo.

set PYTHON_EXE=python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python not found in PATH! 
    echo Please install Python 3.11+ from python.org
    pause
    exit /b
)

if not exist venv (
    echo [System] Creating local virtual environment...
    python -m venv venv
)

echo [System] Activating environment and installing dependencies...
call venv\Scripts\activate
pip install grpcio protobuf numpy >nul 2>nul

echo [System] Launching Product...
echo.
python sentinel_agent.py
pause
