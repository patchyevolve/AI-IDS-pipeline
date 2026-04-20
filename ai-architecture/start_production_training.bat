@echo off
REM Production Training Startup Script for Windows
REM Starts all components for co-evolutionary IDS training

setlocal enabledelayedexpansion

echo.
echo ==========================================
echo CNNFOLE Production Training Startup
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
echo.
echo Checking required files...
set "missing=0"

if not exist "run.py" (
    echo [ERROR] Missing: run.py
    set "missing=1"
)
if not exist "attacker\run_attacker.py" (
    echo [ERROR] Missing: attacker\run_attacker.py
    set "missing=1"
)
if not exist "database\db_engine.py" (
    echo [ERROR] Missing: database\db_engine.py
    set "missing=1"
)
if not exist "database\ids_signatures.jsonl" (
    echo [ERROR] Missing: database\ids_signatures.jsonl
    set "missing=1"
)

if !missing! equ 1 (
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)
echo [OK] All required files found

REM Create logs directory if it doesn't exist
if not exist "logs" mkdir logs

REM Phase 1: Start IDS Training
echo.
echo ==========================================
echo Phase 1: Starting IDS Training
echo ==========================================
echo.
echo Starting: python run.py --synthetic --attack
echo.
start "IDS Training" cmd /k python run.py --synthetic --attack
timeout /t 3 /nobreak

REM Phase 3: Show status
echo.
echo ==========================================
echo Phase 3: Training Started
echo ==========================================
echo.
echo [OK] Training started!
echo.
echo Processes running:
echo   - IDS Training with Attacker (in separate window)
echo   - Validation enabled (real-time FP/FN tracking)
echo.
echo Database files:
echo   - database\ids_signatures.jsonl
echo   - database\refined_threats.jsonl
echo   - database\synthetic_from_datasets.jsonl
echo.
echo Real datasets used:
echo   - real_datasets\ (19 CSV files)
echo.
echo Validation metrics:
echo   - Printed every 5 minutes to console
echo   - Saved to validation\validation_report.json
echo.
echo To stop training:
echo   - Close the IDS Training window
echo.
echo ==========================================
echo Training in progress...
echo ==========================================
echo.
pause
