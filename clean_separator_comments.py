"""Remove decorative separator comments ("──") while keeping the label text.

This script scans the repo for lines like:
    # Something
and replaces them with:
    # Something

It is safe to run multiple times.
"""

import re
from pathlib import Path

root = Path(__file__).resolve().parent
pattern = re.compile(r"^([ \t]*)#\s*─{2}\s*(.+?)\s*(?:─+\s*)?$")

modified_files = []
for path in root.rglob("*"):
    if not path.is_file():
        continue
    if path.match("**/__pycache__/**"):
        continue
    # only text files where this pattern might appear
    if path.suffix.lower() not in {".py", ".md", ".txt", ".json", ".yaml", ".yml"}:
        continue

    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        continue

    lines = text.splitlines(keepends=True)
    changed = False

    for i, line in enumerate(lines):
        m = pattern.match(line.rstrip("\n"))
        if not m:
            continue
        indent, label = m.groups()
        new_line = f"{indent}# {label}\n"
        if new_line != line:
            lines[i] = new_line
            changed = True

    if changed:
        path.write_text("".join(lines), encoding="utf-8")
        modified_files.append(str(path.relative_to(root)))

print(f"Modified files: {len(modified_files)}")
for f in modified_files:
    print(" -", f)
