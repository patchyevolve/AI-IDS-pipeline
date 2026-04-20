@echo off
REM ============================================================================
REM 5-Minute Co-Evolution Test
REM ============================================================================
REM Quick test to verify system is working correctly
REM - Runs co-evolution for 5 minutes
REM - Tracks accuracy, FNR, FPR
REM - Generates test report
REM ============================================================================

setlocal enabledelayedexpansion

REM Get the directory where this script is located
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    pause
    exit /b 1
)

echo.
echo ============================================================================
echo 5-MINUTE CO-EVOLUTION TEST
echo ============================================================================
echo.
echo This test will:
echo   - Run co-evolution for 5 minutes
echo   - Track validation metrics (accuracy, FNR, FPR)
echo   - Generate test report
echo.
echo Starting test...
echo ============================================================================
echo.

python test_coevo_5min.py

if errorlevel 1 (
    echo.
    echo [ERROR] Test failed with exit code %errorlevel%
    pause
    exit /b %errorlevel%
)

echo.
echo ============================================================================
echo Test completed successfully
echo Report saved to: coevo_test_report.json
echo ============================================================================
pause
