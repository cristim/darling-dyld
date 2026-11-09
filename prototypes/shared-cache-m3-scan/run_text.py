#!/usr/bin/env python3 -I
"""Drive `m3_scan text` over the text sub-caches in 128 MiB windows (resumable, one capped run at a time).

Usage: run_text.py <m3_scan binary> <out dir>
Never mounts, unmounts or remounts anything; capped_run.py pauses a window while MemAvailable < 4500 MB.
"""
import os
import subprocess
import sys

CACHE = os.environ.get("M3_CACHE_DIR", os.path.expanduser("~/mnt/macos-cryptex-os/root/System/Library/dyld"))
INDEX = os.environ.get("M3_INDEX", os.path.expanduser("~/tmp-opencode/notes-run-20261105/dyldcache/m0b-index2.tsv"))
HERE = os.path.dirname(os.path.abspath(__file__))
STEP = 0x08000000
# __TEXT extents of the text sub-caches (same ranges as run-m0b.py)
RANGES = [(0x180088000, 0x1e6138000), (0x2235c4000, 0x28f9f4000), (0x2c6e34000, 0x2d1c34000), (0x2d7248000, 0x2d7250000)]


def main():
    binary, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    for lo, hi in RANGES:
        a = lo
        while a < hi:
            b = min(a + STEP, hi)
            out = f"{outdir}/{a:x}.txt"
            if not os.path.exists(out + ".peak"):
                rc = subprocess.run(["python3", "-I", f"{HERE}/capped_run.py", "--cache", out, "--", binary, "text", CACHE, "dyld_shared_cache_arm64e", INDEX, f"{a:x}", f"{b:x}"]).returncode
                if rc:
                    sys.exit(f"window {a:x} failed rc={rc}")
            print(f"window {a:#x}-{b:#x}: {open(out + '.peak').read().strip()}", flush=True)
            a = b


main()
