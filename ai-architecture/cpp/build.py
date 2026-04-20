"""
Build the ids_pipeline C++ extension.

  python build.py          — Release build
  python build.py --debug  — Debug build

Output: ids_pipeline*.pyd (Windows) or ids_pipeline*.so (Linux/Mac)
        copied to ai-architecture/ so `import ids_pipeline` works from run.py
"""
import subprocess, sys, os, shutil, pathlib

ROOT   = pathlib.Path(__file__).parent          # ai-architecture/cpp/
BUILD  = ROOT / "build"
DEST   = ROOT.parent                            # ai-architecture/

build_type = "Debug" if "--debug" in sys.argv else "Release"

BUILD.mkdir(exist_ok=True)

# Configure
subprocess.check_call([
    "cmake", str(ROOT),
    f"-DCMAKE_BUILD_TYPE={build_type}",
    "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=" + str(DEST),
    "-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=" + str(DEST),
], cwd=BUILD)

# Build
jobs = os.cpu_count() or 4
subprocess.check_call([
    "cmake", "--build", str(BUILD),
    "--config", build_type,
    "--parallel", str(jobs),
])

# Copy .pyd/.so to ai-architecture/ root
for ext in ("*.pyd", "*.so"):
    for f in BUILD.rglob(ext):
        dst = DEST / f.name
        shutil.copy2(f, dst)
        print(f"  copied {f.name} → {dst}")

print(f"\n[build] done — import ids_pipeline from {DEST}")
