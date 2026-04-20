#!/usr/bin/env python3
"""
Fresh database initialization from real threat datasets.
Clears old data and rebuilds from scratch with corrected fitness function.
"""
import os
import sys

# Add parent to path
sys.path.insert(0, os.path.dirname(__file__))

from multi_dataset_loader import main as load_datasets

if __name__ == "__main__":
    print("=" * 60)
    print("FRESH DATABASE INITIALIZATION")
    print("=" * 60)
    print("\nLoading all real threat datasets and building database...\n")
    load_datasets()
    print("\n" + "=" * 60)
    print("✓ Fresh database ready for training!")
    print("=" * 60)
