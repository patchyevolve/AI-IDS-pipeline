@echo off
REM ============================================================================
REM AI-IDS Co-Evolution Training System
REM ============================================================================
REM This batch file starts the complete training pipeline with:
REM - CNN Gate + Autoencoder for anomaly detection
REM - RNN for temporal pattern analysis
REM - Hybrid Decoder with adaptive thresholds
REM - Real-time Validator with auto-correction
REM - Attacker co-evolution engine
REM - Threat Intelligence integration
REM ============================================================================

setlocal enabledelayedexpansion

REM Get the directory where this script is located
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.10+ and add it to your PATH
    pause
    exit /b 1
)

REM Check if required packages are installed
echo [INFO] Checking dependencies...
python -c "import torch; import numpy; import pandas; import scapy" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing required packages...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Parse command line arguments
set MODE=synthetic
set ENABLE_ATTACK=--attack
set ENABLE_VALIDATION=--validate
set ENABLE_CPP=
set FORCE_RESET=

:parse_args
if "%~1"=="" goto start_training
if "%~1"=="--live" (
    set MODE=live
    shift
    goto parse_args
)
if "%~1"=="--no-attack" (
    set ENABLE_ATTACK=
    shift
    goto parse_args
)
if "%~1"=="--no-validate" (
    set ENABLE_VALIDATION=
    shift
    goto parse_args
)
if "%~1"=="--cpp" (
    set ENABLE_CPP=--cpp
    shift
    goto parse_args
)
if "%~1"=="--reset" (
    set FORCE_RESET=--reset
    shift
    goto parse_args
)
shift
goto parse_args

:start_training
echo.
echo ============================================================================
echo AI-IDS CO-EVOLUTION TRAINING SYSTEM
echo ============================================================================
echo.
echo Configuration:
echo   Mode:              %MODE%
echo   Attack Engine:     %ENABLE_ATTACK%
echo   Validation:        %ENABLE_VALIDATION%
echo   C++ Backend:       %ENABLE_CPP%
echo   Force Reset:       %FORCE_RESET%
echo.
echo Starting training pipeline...
echo ============================================================================
echo.

REM Start the training pipeline
if "%MODE%"=="live" (
    echo [INFO] Starting in LIVE mode (requires network interface)
    python run.py %ENABLE_ATTACK% %ENABLE_VALIDATION% %ENABLE_CPP% %FORCE_RESET%
) else (
    echo [INFO] Starting in SYNTHETIC mode (no network interface required)
    python run.py --synthetic %ENABLE_ATTACK% %ENABLE_VALIDATION% %ENABLE_CPP% %FORCE_RESET%
)

if errorlevel 1 (
    echo.
    echo [ERROR] Training pipeline failed with exit code %errorlevel%
    pause
    exit /b %errorlevel%
)

echo.
echo ============================================================================
echo Training completed successfully
echo ============================================================================
pause
