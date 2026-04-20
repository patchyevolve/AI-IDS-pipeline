#!/bin/bash

# build_ebpf.sh — Build eBPF kernel program and userspace loader
#
# Requirements:
#   - clang (for eBPF compilation)
#   - llvm-tools
#   - libbpf-dev
#   - libelf-dev
#   - zlib1g-dev
#
# Usage:
#   ./build_ebpf.sh [clean]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_ebpf"
KERNEL_SRC="${KERNEL_SRC:-/usr/src/linux-headers-$(uname -r)}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[eBPF Build] Starting eBPF build process${NC}"

# Check for clean flag
if [ "$1" == "clean" ]; then
    echo -e "${YELLOW}[eBPF Build] Cleaning build directory${NC}"
    rm -rf "${BUILD_DIR}"
    exit 0
fi

# Create build directory
mkdir -p "${BUILD_DIR}"

# Check dependencies
echo -e "${YELLOW}[eBPF Build] Checking dependencies${NC}"

for cmd in clang llc pkg-config; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}[eBPF Build] ERROR: $cmd not found${NC}"
        echo "Install with: sudo apt-get install clang llvm libelf-dev zlib1g-dev libbpf-dev"
        exit 1
    fi
done

# Compile eBPF kernel program
echo -e "${YELLOW}[eBPF Build] Compiling eBPF kernel program${NC}"

KERNEL_OBJ="${BUILD_DIR}/ebpf_kernel.o"

clang -O2 -target bpf \
    -D__KERNEL__ \
    -D__BPF_TRACING__ \
    -I/usr/include/bpf \
    -c "${SCRIPT_DIR}/ebpf_kernel.c" \
    -o "${KERNEL_OBJ}"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[eBPF Build] ✓ Compiled: ${KERNEL_OBJ}${NC}"
else
    echo -e "${RED}[eBPF Build] ERROR: Failed to compile eBPF kernel program${NC}"
    exit 1
fi

# Verify eBPF object
echo -e "${YELLOW}[eBPF Build] Verifying eBPF object${NC}"

llvm-objdump -d "${KERNEL_OBJ}" | head -20

# Compile userspace loader
echo -e "${YELLOW}[eBPF Build] Compiling userspace loader${NC}"

LOADER_BIN="${BUILD_DIR}/ebpf_loader"

g++ -O2 -std=c++17 \
    -I/usr/include \
    -I"${SCRIPT_DIR}" \
    "${SCRIPT_DIR}/ebpf_loader.cpp" \
    -o "${LOADER_BIN}" \
    -lbpf -lelf -lz

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[eBPF Build] ✓ Compiled: ${LOADER_BIN}${NC}"
else
    echo -e "${RED}[eBPF Build] ERROR: Failed to compile userspace loader${NC}"
    exit 1
fi

# Compile integration library
echo -e "${YELLOW}[eBPF Build] Compiling integration library${NC}"

INTEGRATION_OBJ="${BUILD_DIR}/ebpf_integration.o"

g++ -O2 -std=c++17 -fPIC \
    -I/usr/include \
    -I"${SCRIPT_DIR}" \
    -c "${SCRIPT_DIR}/ebpf_integration.cpp" \
    -o "${INTEGRATION_OBJ}"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[eBPF Build] ✓ Compiled: ${INTEGRATION_OBJ}${NC}"
else
    echo -e "${RED}[eBPF Build] ERROR: Failed to compile integration library${NC}"
    exit 1
fi

# Create shared library
echo -e "${YELLOW}[eBPF Build] Creating shared library${NC}"

INTEGRATION_LIB="${BUILD_DIR}/libebpf_integration.so"

g++ -shared -O2 -std=c++17 \
    "${INTEGRATION_OBJ}" \
    -o "${INTEGRATION_LIB}" \
    -lbpf -lelf -lz

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[eBPF Build] ✓ Created: ${INTEGRATION_LIB}${NC}"
else
    echo -e "${RED}[eBPF Build] ERROR: Failed to create shared library${NC}"
    exit 1
fi

# Summary
echo -e "${GREEN}[eBPF Build] Build complete!${NC}"
echo ""
echo "Artifacts:"
echo "  Kernel program:  ${KERNEL_OBJ}"
echo "  Userspace loader: ${LOADER_BIN}"
echo "  Integration lib:  ${INTEGRATION_LIB}"
echo ""
echo "Next steps:"
echo "  1. Load kernel program:"
echo "     sudo ${LOADER_BIN} eth0 ${KERNEL_OBJ}"
echo ""
echo "  2. Link integration library in your project:"
echo "     g++ -o myapp myapp.cpp -L${BUILD_DIR} -lebpf_integration -lbpf"
echo ""

