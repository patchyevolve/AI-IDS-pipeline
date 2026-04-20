@echo off
REM Extended Production Training Script for Windows
REM Runs for a specified duration to accumulate more training data

setlocal enabledelayedexpansion

echo.
echo ==========================================
echo CNNFOLE Extended Training Session
echo ==========================================
echo.

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.9+
    pause
    exit /b 1
)
echo [OK] Python found

REM Check required files
if not exist "run.py" (
    echo [ERROR] Missing: run.py
    pause
    exit /b 1
)
if not exist "attacker\run_attacker.py" (
    echo [ERROR] Missing: attacker\run_attacker.py
    pause
    exit /b 1
)
echo [OK] All required files found

REM Create logs directory if it doesn't exist
if not exist "logs" mkdir logs

REM Training duration in seconds (3600 = 1 hour, 7200 = 2 hours, etc.)
set "DURATION=3600"

echo.
echo Training Configuration:
echo   Duration: %DURATION% seconds
echo   IDS: python run.py --synthetic
echo   Attacker: python attacker/run_attacker.py --remote 127.0.0.1 --synthetic
echo.
echo Starting training...
echo.

REM Phase 1: Start IDS Training
start "IDS Training" cmd /k python run.py --synthetic
timeout /t 3 /nobreak

REM Phase 2: Start Attacker Evolution with duration
start "Attacker Evolution" cmd /k python attacker/run_attacker.py --remote 127.0.0.1 --synthetic --duration %DURATION%
timeout /t 3 /nobreak

REM Phase 3: Show status
echo.
echo ==========================================
echo Training Session Started
echo ==========================================
echo.
echo [OK] Training started!
echo.
echo Processes running:
echo   - IDS Training (in separate window)
echo   - Attacker Evolution (in separate window, will run for %DURATION% seconds)
echo.
echo Database files:
echo   - database\ids_signatures.jsonl
echo   - database\refined_threats.jsonl
echo   - database\synthetic_from_datasets.jsonl
echo.
echo To stop training early:
echo   - Close the IDS Training window
echo   - Close the Attacker Evolution window
echo.
echo ==========================================
echo Training in progress...
echo ==========================================
echo.
pause
