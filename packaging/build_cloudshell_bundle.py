"""Build dist/skyveda-cloudshell-<version>.zip: the wheel, install.sh and README.txt.

uv run python packaging/build_cloudshell_bundle.py
"""

# ruff: noqa: T201, S603, S607 - a build script: prints progress and runs `uv build`.

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "packaging" / "cloudshell"
DIST = ROOT / "dist"
FOLDER = "skyveda-cloudshell"


def main() -> int:
    for old in DIST.glob("skyveda-*"):
        old.unlink()
    subprocess.run(["uv", "build", "--wheel", "--out-dir", str(DIST)], cwd=ROOT, check=True)
    wheels = sorted(DIST.glob("skyveda-*.whl"))
    if len(wheels) != 1:
        print(f"Expected one wheel in {DIST}, found {len(wheels)}.")
        return 1
    wheel = wheels[0]
    version = wheel.name.split("-")[1]
    bundle = DIST / f"skyveda-cloudshell-{version}.zip"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(wheel, f"{FOLDER}/{wheel.name}")
        for name in ("install.sh", "README.txt"):
            # Linux line endings, and install.sh executable, whatever the build machine is.
            text = (SOURCE / name).read_text(encoding="utf-8").replace("\r\n", "\n")
            info = zipfile.ZipInfo(f"{FOLDER}/{name}")
            info.external_attr = (0o755 if name.endswith(".sh") else 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, text)
    print(f"Wrote {bundle.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
