#!/usr/bin/env python3 -I
"""Run one command under the heavy-build lock, a 3 GB systemd scope and a memory watchdog.

Usage: capped_run.py [--cache] OUT.txt -- cmd args...
  --cache   hold the shared flock on the cryptex mount lock while the command runs (it reads the cache)
Watchdog (1 s): MemAvailable < 4500 MB pauses the command (SIGSTOP) until it recovers; < 3500 MB aborts it.
stdout goes to OUT.txt, stderr to OUT.txt.err; one line "peak ..." is appended to OUT.txt.peak.
The cryptex mount itself is never touched.
"""
import os
import signal
import subprocess
import sys
import threading
import time

LOCK = os.environ.get("M3_CRYPTEX_LOCK", os.path.expanduser("~/tmp-opencode/notes-run-20261105/cryptex-mount.lock"))
HEAVY = "/tmp/agent-locks/darling-heavy-build.lock"
PAUSE_MB, ABORT_MB = 4500, 3500


def avail_mb():
    for line in open("/proc/meminfo"):
        if line.startswith("MemAvailable"):
            return int(line.split()[1]) // 1024


def fuse_rss_mb():
    out = subprocess.run(["pgrep", "-u", str(os.getuid()), "-f", "apfs-fuse.*macos-cryptex-os"], capture_output=True, text=True).stdout.split()
    for pid in out[:1]:
        try:
            for line in open(f"/proc/{pid}/status"):
                if line.startswith("VmRSS"):
                    return int(line.split()[1]) // 1024
        except OSError:
            pass
    return 0


def main():
    args = sys.argv[1:]
    use_cache = False
    if args and args[0] == "--cache":
        use_cache, args = True, args[1:]
    out, cmd = args[0], args[args.index("--") + 1:]
    while avail_mb() < PAUSE_MB:
        print(f"waiting: MemAvailable {avail_mb()} MB < {PAUSE_MB}", flush=True)
        time.sleep(15)
    # the shared cryptex lock is taken only while the command runs (inside the heavy lock), never while queueing
    shared = ["flock", "-s", LOCK] if use_cache else []
    full = ["flock", "-w", "900", "-E", "99", HEAVY, "systemd-run", "--user", "--scope", "--quiet", "-p", "MemoryMax=3G", "-p", "MemorySwapMax=0"] + shared + ["timeout", "600"] + cmd
    stats = {"min_avail": avail_mb(), "max_fuse": fuse_rss_mb(), "paused": 0, "aborted": False}
    done = threading.Event()
    with open(out, "w") as fo, open(out + ".err", "w") as fe:
        p = None

        def watch():
            paused = False
            while not done.is_set():
                a = avail_mb()
                stats["min_avail"] = min(stats["min_avail"], a)
                stats["max_fuse"] = max(stats["max_fuse"], fuse_rss_mb())
                if a < ABORT_MB:
                    stats["aborted"] = True
                    os.killpg(p.pid, signal.SIGTERM)
                    return
                if a < PAUSE_MB and not paused:
                    os.killpg(p.pid, signal.SIGSTOP)
                    paused = True
                    stats["paused"] += 1
                elif a >= PAUSE_MB + 300 and paused:
                    os.killpg(p.pid, signal.SIGCONT)
                    paused = False
                time.sleep(1)
            if paused:
                os.killpg(p.pid, signal.SIGCONT)

        for attempt in range(48):  # another session may hold the heavy lock for hours: keep queueing (flock exit 99 = timed out)
            p = subprocess.Popen(full, stdout=fo, stderr=fe, start_new_session=True, pass_fds=())
            done.clear()
            t = threading.Thread(target=watch, daemon=True)
            t.start()
            rc = p.wait()
            done.set()
            t.join()
            if rc != 99:
                break
            fo.seek(0); fo.truncate()
    with open(out + ".peak", "a") as f:
        f.write(f"rc={rc} min_avail_mb={stats['min_avail']} max_fuse_rss_mb={stats['max_fuse']} pauses={stats['paused']} aborted={stats['aborted']}\n")
    sys.exit(rc)


main()
