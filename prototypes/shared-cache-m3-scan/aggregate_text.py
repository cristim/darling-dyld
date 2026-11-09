#!/usr/bin/env python3 -I
"""Aggregate `m3_scan text` window outputs: per image group, commpage sites and distinct offsets; svc and TSD counts.

Usage: aggregate_text.py <window dir> [<pool re-pass dir>] <arm64 cpu_capabilities.h> <mldr commpage.c>
The optional second directory holds `W` lines recomputed by a later run restricted to some images (`text ... <only-file>`);
its W lines replace the originals. Prints a Markdown-ish report on stdout. Reads no cache bytes.
"""
import collections
import glob
import re
import sys

args = [a for a in sys.argv[1:]]
WIN = args[0]
REPASS = args[1] if len(args) == 4 else None
HDR, MLDR = args[-2], args[-1]

GROUPS = [
    ("libsystem_kernel", lambda p: p == "/usr/lib/system/libsystem_kernel.dylib"),
    ("libsystem_c", lambda p: p == "/usr/lib/system/libsystem_c.dylib"),
    ("libsystem_pthread", lambda p: p == "/usr/lib/system/libsystem_pthread.dylib"),
    ("libsystem_platform", lambda p: p == "/usr/lib/system/libsystem_platform.dylib"),
    ("libsystem_malloc", lambda p: p == "/usr/lib/system/libsystem_malloc.dylib"),
    ("libdispatch", lambda p: p == "/usr/lib/system/libdispatch.dylib"),
    ("libdyld", lambda p: p == "/usr/lib/system/libdyld.dylib"),
    ("libobjc", lambda p: p == "/usr/lib/libobjc.A.dylib"),
    ("CoreFoundation", lambda p: "/CoreFoundation.framework/" in p),
    ("libSystem.B", lambda p: p == "/usr/lib/libSystem.B.dylib"),
    ("libc++/libc++abi", lambda p: p in ("/usr/lib/libc++.1.dylib", "/usr/lib/libc++abi.dylib")),
    ("/usr/lib/dyld (the cache's own dyld, replaced by Darling's)", lambda p: p == "/usr/lib/dyld"),
    ("other libsystem_*", lambda p: p.startswith("/usr/lib/system/")),
    ("all other images", lambda p: True),
]


def group_of(path):
    for name, f in GROUPS:
        if f(path):
            return name


def parse_acc(s):
    out = []
    for item in s.split(","):
        if not item:
            continue
        off, size, kind, cnt = item.split(":")
        out.append((int(off), int(size), kind, int(cnt)))
    return out


img = {}  # path -> dict
def rec(path):
    return img.setdefault(path, dict(insns=0, svc=0, tsd_in=0, tsd_ot=0, sites=0, access_sites=0, lits=0, acc=collections.Counter(), pool_sites=0, pool_access=0, pool_acc=collections.Counter(), qwords={}, hi_f=0, hi_ffff=0, formed={}))

def read_dir(d, only_w=False):
    for fn in sorted(glob.glob(f"{d}/*.txt")):
        for line in open(fn):
            f = line.rstrip("\n").split("\t")
            if f[0] == "P" and not only_w:
                r = rec(f[1])
                r.update(insns=int(f[2]), svc=int(f[3]), tsd_in=int(f[4]), tsd_ot=int(f[5]), sites=int(f[6]), access_sites=int(f[7]), lits=int(f[8]))
            elif f[0] == "O" and not only_w:
                for off, size, kind, cnt in parse_acc(f[2]):
                    rec(f[1])["acc"][(off, size, kind)] += cnt
            elif f[0] == "H" and not only_w:
                r = rec(f[1])
                r["hi_f"], r["hi_ffff"] = int(f[2]), int(f[3])
                for item in (f[4].split(",") if len(f) > 4 and f[4] else []):
                    v, n = item.split(":")
                    r["formed"][int(v, 16)] = int(n)
            elif f[0] == "Q" and not only_w:
                rec(f[1])["qwords"] = {int(k): int(v) for k, v in (x.split(":") for x in f[2].split(","))}
            elif f[0] == "W":
                r = rec(f[1])
                if only_w and not r.get("_w_reset"):
                    r["pool_sites"], r["pool_access"], r["pool_acc"], r["_w_reset"] = 0, 0, collections.Counter(), True
                r["pool_sites"] = int(f[2])
                r["pool_access"] = int(f[3])
                for off, size, kind, cnt in parse_acc(f[4] if len(f) > 4 else ""):
                    r["pool_acc"][(off, size, kind)] += cnt


read_dir(WIN)
if REPASS:
    read_dir(REPASS, only_w=True)

# commpage field names from the arm64 header (offsets relative to the base)
names = {}
for m in re.finditer(r"#define\s+(_COMM_PAGE_[A-Z0-9_]+)\s+\(_COMM_PAGE_START_ADDRESS\+(0x[0-9A-Fa-f]+)\)", open(HDR).read()):
    names.setdefault(int(m.group(2), 16), m.group(1))

# fields mldr fills (commpage_setup in commpage.c): offset, length. Zero-filled anonymous mapping otherwise.
mldr_src = open(MLDR).read()
FILLED = [(0x000, 0x10, "signature"), (0x010, 8, "cpu_capabilities64"), (0x01e, 2, "version"), (0x020, 4, "cpu_capabilities (uint32)"),
          (0x022, 1, "ncpus"), (0x025, 1, "user_page_shift_64"), (0x034, 1, "active_cpus"), (0x035, 1, "physical_cpus"), (0x036, 1, "logical_cpus"),
          (0x037, 1, "kernel_page_shift"), (0x038, 8, "memory_size")]
for _, _, what in FILLED:
    key = {"signature": "_COMM_PAGE_SIGNATURE", "cpu_capabilities64": "_COMM_PAGE_CPU_CAPABILITIES64", "version": "_COMM_PAGE_VERSION", "ncpus": "_COMM_PAGE_NCPUS"}.get(what)
    if key and key not in mldr_src:
        sys.exit(f"mldr no longer references {key}; update FILLED")


def provided(off, size):
    return any(off >= a and off + max(size, 1) <= a + n for a, n, _ in FILLED)


# sizes of the header fields longer than 8 bytes (from the comments in cpu_capabilities.h); every other field is at most 8 bytes
LONG_FIELDS = {0x000: 0x10, 0x040: 40, 0x120: 40, 0x148: 24, 0x180: 128}


def label(off):
    best = max((o for o in names if o <= off), default=None)
    if best is None:
        return "?"
    if off - best >= LONG_FIELDS.get(best, 8):
        return f"not a field of Darling's header (after {names[best]}+{LONG_FIELDS.get(best, 8):#x})"
    return f"{names[best]}+{off - best:#x}"


def fmt_acc(c):
    return ", ".join(f"{off:#x}:{size}B{kind}" if off >= 0 else "reg" for (off, size, kind) in sorted(c))


tot = collections.defaultdict(lambda: dict(images=0, with_sites=0, sites=0, access=0, acc=collections.Counter(), svc=0, tsd=0, qw=0, hi_f=0, outside=collections.Counter()))
for path, r in img.items():
    g = tot[group_of(path)]
    g["images"] += 1
    s = r["sites"] + r["pool_sites"]
    g["sites"] += s
    g["access"] += r["access_sites"] + r["pool_access"]
    g["with_sites"] += 1 if s or r["lits"] else 0
    g["svc"] += r["svc"]
    g["tsd"] += r["tsd_in"] + r["tsd_ot"]
    g["qw"] += r["lits"]
    g["hi_f"] += r["hi_f"]
    for v, n in r["formed"].items():
        if not (0xFFFFFC000 <= v < 0x1000000000):
            g["outside"][v] += n
    for k, v in list(r["acc"].items()) + list(r["pool_acc"].items()):
        g["acc"][k] += v

print("# commpage reads per image group (formation sites by mov-wide sequence or by load of a literal that holds the address;")
print("# accesses = load/store through the formed register inside a 24-instruction window)")
all_offs = collections.Counter()
for name, _ in GROUPS:
    g = tot[name]
    print(f"\n## {name}: {g['images']} images, {g['with_sites']} with commpage formation or literal, {g['sites']} sites, {g['access']} with an access, {g['qw']} 8-byte literals in __TEXT; svc {g['svc']}, mrs TPIDRRO_EL0 {g['tsd']}")
    offs = sorted({k[0] for k in g["acc"]})
    print(f"   cross-check: {g['hi_f']} `movk/movz #0xf, lsl #32` instructions; constants with 0xf at bit 32 formed but outside the commpage page: " + (", ".join(f"{v:#x} x{n}" for v, n in g["outside"].most_common(4)) or "none"))
    print(f"   distinct offsets {len(offs)}: " + " ".join(f"{o:#x}" for o in offs if o >= 0) + (" + register-offset forms" if any(o < 0 for o in offs) else ""))
    for k, v in g["acc"].items():
        all_offs[k] += v
print("\n# offsets read anywhere in the cache (by access), with the field name from arm64 cpu_capabilities.h and mldr coverage")
missing = []
for (off, size, kind), n in sorted(all_offs.items()):
    if off < 0:
        continue
    prov = provided(off, size)
    if not prov:
        missing.append((off, size, kind, n))
    print(f"{off:#06x} {size}B {kind} x{n:<6} {label(off)}: {'provided by mldr' if prov else 'NOT provided (reads zero)'}")
print(f"\n# read offsets not provided by mldr: {len({m[0] for m in missing})} distinct")
print("# top images outside the libSystem family by commpage sites")
rows = sorted(((r["sites"] + r["pool_sites"], p) for p, r in img.items() if group_of(p) == "all other images"), reverse=True)[:15]
for n, p in rows:
    if n:
        print(f"{n:6} {p}")
