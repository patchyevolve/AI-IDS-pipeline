#!/bin/bash
# Production Training Startup Script
# Starts all components for co-evolutionary IDS training

set -e

echo "=========================================="
echo "CNNFOLE Production Training Startup"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python
if ! command -v python &> /dev/null; then
    echo -e "${RED}❌ Python not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python found${NC}"

# Check required files
echo ""
echo "Checking required files..."
required_files=(
    "multi_dataset_loader.py"
    "run.py"
    "attacker/run_attacker.py"
    "diagnose_system.py"
    "database/db_engine.py"
)

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}❌ Missing: $file${NC}"
        exit 1
    fi
done
echo -e "${GREEN}✓ All required files found${NC}"

# Phase 1: Load CSV data
echo ""
echo "=========================================="
echo "Phase 1: Loading Real Threat Data"
echo "=========================================="
python csv_threat_loader.py

# Verify database
echo ""
echo "Verifying database..."
python diagnose_system.py | head -30

# Phase 2: Start IDS
echo ""
echo "=========================================="
echo "Phase 2: Starting IDS Training"
echo "=========================================="
echo -e "${YELLOW}Starting IDS in background...${NC}"
python run.py > logs/ids_training.log 2>&1 &
IDS_PID=$!
echo -e "${GREEN}✓ IDS started (PID: $IDS_PID)${NC}"

# Wait for IDS to initialize
sleep 5

# Phase 3: Start Attacker
echo ""
echo "=========================================="
echo "Phase 3: Starting Attacker Evolution"
echo "=========================================="
echo -e "${YELLOW}Starting Attacker in background...${NC}"
cd attacker
python run_attacker.py --remote > logs/attacker_training.log 2>&1 &
ATTACKER_PID=$!
cd ..
echo -e "${GREEN}✓ Attacker started (PID: $ATTACKER_PID)${NC}"

# Wait for attacker to initialize
sleep 5

# Phase 4: Start monitoring
echo ""
echo "=========================================="
echo "Phase 4: Starting Monitoring"
echo "=========================================="
echo -e "${GREEN}✓ Training started!${NC}"
echo ""
echo "Processes running:"
echo "  IDS (PID: $IDS_PID)"
echo "  Attacker (PID: $ATTACKER_PID)"
echo ""
echo "Logs:"
echo "  IDS: logs/ids_training.log"
echo "  Attacker: logs/attacker_training.log"
echo ""
echo "Monitor progress with:"
echo "  python diagnose_system.py"
echo "  python diagnose_live.py"
echo ""
echo "Stop training with:"
echo "  kill $IDS_PID $ATTACKER_PID"
echo ""
echo "=========================================="
echo "Training in progress..."
echo "=========================================="

# Keep script running and show periodic updates
while true; do
    sleep 300  # Every 5 minutes
    echo ""
    echo "[$(date)] Checking status..."
    
    # Check if processes are still running
    if ! kill -0 $IDS_PID 2>/dev/null; then
        echo -e "${RED}❌ IDS process died!${NC}"
        break
    fi
    
    if ! kill -0 $ATTACKER_PID 2>/dev/null; then
        echo -e "${RED}❌ Attacker process died!${NC}"
        break
    fi
    
    # Show brief status
    python diagnose_system.py 2>/dev/null | grep -E "records|signatures|Block|Evasion|Generations" || true
done

echo ""
echo "Training stopped."
