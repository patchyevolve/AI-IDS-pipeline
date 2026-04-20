#!/bin/bash
# Build eBPF program for Linux

set -e

echo "[eBPF] Building eBPF XDP program..."

# Check if clang is installed
if ! command -v clang &> /dev/null; then
    echo "[ERROR] clang not found. Install with:"
    echo "  Ubuntu/Debian: sudo apt-get install clang llvm"
    echo "  Fedora: sudo dnf install clang llvm"
    echo "  macOS: brew install llvm"
    exit 1
fi

# Check if libbpf headers are available
if [ ! -f "/usr/include/bpf/bpf.h" ] && [ ! -f "/usr/local/include/bpf/bpf.h" ]; then
    echo "[WARNING] libbpf headers not found. Install with:"
    echo "  Ubuntu/Debian: sudo apt-get install libbpf-dev"
    echo "  Fedora: sudo dnf install libbpf-devel"
    echo "  macOS: brew install libbpf"
    echo ""
    echo "Continuing without libbpf support..."
fi

# Compile BPF program
echo "[eBPF] Compiling ids_ebpf.bpf.c..."
clang -O2 -target bpf -c ids_ebpf.bpf.c -o ids_ebpf.bpf.o

if [ -f "ids_ebpf.bpf.o" ]; then
    echo "[OK] eBPF program compiled: ids_ebpf.bpf.o"
    ls -lh ids_ebpf.bpf.o
else
    echo "[ERROR] Failed to compile eBPF program"
    exit 1
fi

echo "[eBPF] Build complete!"
