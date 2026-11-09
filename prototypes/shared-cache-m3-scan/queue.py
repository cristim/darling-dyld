#!/usr/bin/env python3 -I
"""Run the remaining 3.0b jobs one after the other (each through capped_run.py, which queues on the heavy lock).
Usage: queue.py <m3_scan binary> <notes dir>   Resumable: a finished job leaves <out>.peak and is skipped."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.environ.get("M3_CACHE_DIR", os.path.expanduser("~/mnt/macos-cryptex-os/root/System/Library/dyld"))
INDEX = os.environ.get("M3_INDEX", os.path.expanduser("~/tmp-opencode/notes-run-20261105/dyldcache/m0b-index2.tsv"))
BASE = "dyld_shared_cache_arm64e"
LEAFS = ["/usr/lib/libz.1.dylib", "/usr/lib/libbz2.1.0.dylib", "/usr/lib/libcompression.dylib", "/usr/lib/liblzma.5.dylib", "/usr/lib/libxml2.2.dylib",
         "/usr/lib/libsqlite3.dylib", "/usr/lib/libiconv.2.dylib", "/usr/lib/libresolv.9.dylib", "/usr/lib/libexpat.1.dylib", "/usr/lib/libffi.dylib", "/usr/lib/libcharset.1.dylib"]
FAMILY = ["/usr/lib/system/libsystem_kernel.dylib", "/usr/lib/system/libsystem_c.dylib", "/usr/lib/system/libsystem_pthread.dylib", "/usr/lib/system/libsystem_platform.dylib",
          "/usr/lib/system/libsystem_malloc.dylib", "/usr/lib/system/libdispatch.dylib", "/usr/lib/system/libdyld.dylib", "/usr/lib/libobjc.A.dylib", "/usr/lib/libSystem.B.dylib",
          "/usr/lib/libc++.1.dylib", "/usr/lib/libc++abi.dylib", "/usr/lib/system/libsystem_blocks.dylib", "/usr/lib/system/libsystem_info.dylib", "/usr/lib/system/libsystem_m.dylib",
          "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"]


def job(binary, out, *args):
    if os.path.exists(out + ".peak") and "rc=0" in open(out + ".peak").read():
        return
    rc = subprocess.run(["python3", "-I", f"{HERE}/capped_run.py", "--cache", out, "--", binary, args[0], CACHE, BASE, INDEX, *args[1:]]).returncode
    print(f"{os.path.basename(out)}: rc={rc} {open(out + '.peak').read().strip()}", flush=True)
    if rc:
        sys.exit(1)


def main():
    binary, notes = sys.argv[1], sys.argv[2]
    m3 = f"{notes}/m3"
    os.makedirs(m3, exist_ok=True)
    job(binary, f"{m3}/hdr.txt", "hdr")
    job(binary, f"{m3}/patchcheck.txt", "patchcheck")
    job(binary, f"{m3}/patchsample.txt", "patchsample", "40", "100")
    job(binary, f"{m3}/patchclient-libz.txt", "patchclient", "/usr/lib/libz.1.dylib", "list", "40")
    job(binary, f"{m3}/sections-libz.txt", "sections", "/usr/lib/libz.1.dylib")
    job(binary, f"{m3}/sections-libSystem.txt", "sections", "/usr/lib/libSystem.B.dylib")
    job(binary, f"{m3}/imgexports-libSystem.txt", "imgexports", "/usr/lib/libSystem.B.dylib")
    job(binary, f"{m3}/slots-libz.txt", "slots", "/usr/lib/libz.1.dylib")
    job(binary, f"{m3}/stubs-libz.txt", "stubs", "/usr/lib/libz.1.dylib", "1902aff2c", "110")
    job(binary, f"{m3}/initwalk-libSystem.txt", "initwalk", "/usr/lib/libSystem.B.dylib", "200")
    job(binary, f"{m3}/imports-leafs-flags.txt", "imports", *LEAFS)
    job(binary, f"{m3}/dataq-family.txt", "dataq", *FAMILY)
    subprocess.run(["python3", "-I", f"{HERE}/run_text.py", binary, f"{notes}/m3win2"], check=True)


main()
