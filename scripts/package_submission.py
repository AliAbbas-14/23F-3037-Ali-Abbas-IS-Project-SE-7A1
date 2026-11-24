"""Create clean submission ZIP archive excluding virtualenvs, caches, and runtime secrets."""

from __future__ import annotations

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_ZIP = ROOT / "23F-3037_IS_Project_App.zip"

EXCLUDE_DIRS = {
    ".venv",
    ".git",
    "__pycache__",
    ".pytest_cache",
    "storage",
    "tmp_demo_capture",
    "tmp_test_storage",
}

EXCLUDE_FILES = {
    OUT_ZIP.name,
    ".env",
    "CS3002___Information_Security.pdf",
}


def build_zip() -> None:
    if OUT_ZIP.exists():
        OUT_ZIP.unlink()

    added = 0
    with zipfile.ZipFile(OUT_ZIP, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(ROOT.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(ROOT)
            if any(part in EXCLUDE_DIRS for part in rel.parts):
                continue
            if path.name in EXCLUDE_FILES or path.suffix in {".zip", ".pyc", ".log"}:
                continue
            zf.write(path, arcname=f"VaultGuard_SDMS_23F-3037/{rel.as_posix()}")
            added += 1

    print(f"Packaged {added} clean source/doc files into {OUT_ZIP.name} ({OUT_ZIP.stat().st_size} bytes)")


if __name__ == "__main__":
    build_zip()
