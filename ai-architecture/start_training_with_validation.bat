@echo off
REM Production Training with Real-Time Validation & Auto-Correction
REM Tracks FP/FN and automatically corrects database mistakes

setlocal enabledelayedexpansion

echo.
echo ==========================================
echo CNNFOLE Training with Auto-Correction
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
if not exist "validation" mkdir validation

echo.
echo Training Configuration:
echo   Mode: Synthetic with Real-Time Validation
echo   IDS: python run.py --synthetic --validate
echo   Attacker: python attacker/run_attacker.py --remote 127.0.0.1 --synthetic
echo.
echo Features:
echo   - Tracks False Positives (FP) and False Negatives (FN)
echo   - Auto-corrects database when errors detected
echo   - Prevents same mistakes from happening again
echo   - Generates validation report at end
echo.
echo Starting training...
echo.

REM Phase 1: Start IDS Training with validation
start "IDS Training (with Validation)" cmd /k python run.py --synthetic --validate
timeout /t 3 /nobreak

REM Phase 2: Start Attacker Evolution
start "Attacker Evolution" cmd /k python attacker/run_attacker.py --remote 127.0.0.1 --synthetic
timeout /t 3 /nobreak

REM Phase 3: Show status
echo.
echo ==========================================
echo Training Session Started
echo ==========================================
echo.
echo [OK] Training started with auto-correction!
echo.
echo Processes running:
echo   - IDS Training (with validation enabled)
echo   - Attacker Evolution
echo.
echo Real-Time Monitoring:
echo   - FP/FN detected automatically
echo   - Database corrected in real-time
echo   - Metrics updated every 5 minutes
echo.
echo Output Files:
echo   - validation\validation_report.json (final metrics)
echo   - validation\metrics_timeline.jsonl (per-event log)
echo.
echo To stop training:
echo   - Close the IDS Training window
echo   - Close the Attacker Evolution window
echo.
echo ==========================================
echo Training in progress...
echo ==========================================
echo.
pause
