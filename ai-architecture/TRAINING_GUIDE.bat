@echo off
REM ============================================================================
REM AI-IDS Training Guide
REM ============================================================================

cls
echo.
echo ============================================================================
echo AI-IDS CO-EVOLUTION TRAINING SYSTEM - QUICK START GUIDE
echo ============================================================================
echo.
echo AVAILABLE COMMANDS:
echo.
echo 1. QUICK TEST (5 minutes):
echo    test_5min.bat
echo    - Runs a 5-minute co-evolution test
echo    - Generates accuracy/FNR/FPR metrics
echo    - Good for verifying system is working
echo.
echo 2. FULL TRAINING (Synthetic Mode):
echo    train.bat
echo    - Starts full training pipeline
echo    - Uses synthetic attack data (no network interface needed)
echo    - Includes: CNN, RNN, Decoder, Validator, Attacker, Threat Intelligence
echo    - Press Ctrl+C to stop
echo.
echo 3. LIVE TRAINING (Network Mode):
echo    train.bat --live
echo    - Captures real network traffic
echo    - Requires network interface selection
echo    - Includes all features from synthetic mode
echo    - Press Ctrl+C to stop
echo.
echo 4. TRAINING WITHOUT ATTACK ENGINE:
echo    train.bat --no-attack
echo    - Runs pipeline without attacker co-evolution
echo    - Useful for testing detection only
echo.
echo 5. TRAINING WITHOUT VALIDATION:
echo    train.bat --no-validate
echo    - Runs pipeline without real-time validator
echo    - Useful for baseline testing
echo.
echo 6. TRAINING WITH C++ BACKEND:
echo    train.bat --cpp
echo    - Uses C++ eBPF for packet capture
echo    - Keeps Python decoder for full features
echo    - Better performance on Linux
echo.
echo 7. RESET DATABASE AND RETRAIN:
echo    train.bat --reset
echo    - Clears previous database
echo    - Starts fresh training
echo.
echo ============================================================================
echo SYSTEM COMPONENTS:
echo ============================================================================
echo.
echo CNN Engine:
echo   - Gate classifier (attack vs normal)
echo   - Autoencoder for anomaly detection
echo   - Adaptive thresholds per source IP
echo.
echo RNN Engine:
echo   - Temporal pattern analysis
echo   - Anomaly trend detection
echo   - Drift score calculation
echo.
echo Hybrid Decoder:
echo   - Fuses CNN + RNN + Database signals
echo   - Attention-based token pooling
echo   - Correlation engine for multi-stage attacks
echo.
echo Real-time Validator:
echo   - Detects false negatives (missed attacks)
echo   - Detects false positives (blocked benign traffic)
echo   - Auto-corrects database with confidence=0.95
echo   - Exports corrected signatures immediately
echo.
echo Attacker Co-Evolution:
echo   - Generates diverse attack profiles
echo   - Learns from IDS decisions
echo   - Evolves evasion tactics
echo   - Provides ground truth for validation
echo.
echo Threat Intelligence:
echo   - MITRE ATT&CK mapping
echo   - Campaign correlation
echo   - Behavioral baseline analysis
echo   - Threat actor attribution
echo.
echo ============================================================================
echo EXPECTED PERFORMANCE:
echo ============================================================================
echo.
echo After 5 minutes of training:
echo   - Accuracy: 98%+
echo   - False Negative Rate: 1-2%%
echo   - False Positive Rate: 0%%
echo   - Attacker Generations: 10-12
echo   - Database Size: 8,800+ signatures
echo.
echo ============================================================================
echo TROUBLESHOOTING:
echo ============================================================================
echo.
echo If you see "Python is not installed":
echo   - Install Python 3.10+ from python.org
echo   - Add Python to your PATH
echo   - Restart your terminal
echo.
echo If you see "Failed to install dependencies":
echo   - Run: pip install -r requirements.txt
echo   - Check your internet connection
echo   - Try: pip install --upgrade pip
echo.
echo If training is slow:
echo   - Close other applications
echo   - Use --synthetic mode instead of --live
echo   - Check CPU/GPU usage
echo.
echo If you see network errors:
echo   - Use --synthetic mode (doesn't need network)
echo   - Check firewall settings
echo   - Verify network interface is available
echo.
echo ============================================================================
echo.
pause
