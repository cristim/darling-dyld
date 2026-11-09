#!/usr/bin/env python3 -I
"""Compare symbols the cache images need against what Darling's built dylibs export (read-only).

Usage: compare_exports.py <m3_exports binary> <darling build root> <needs.tsv> [--lib-only]
needs.tsv: lines "exporter install name<TAB>symbol" (other columns ignored; lines not matching are skipped).
Darling provides a symbol when some dylib in the re-export closure of its libSystem.B (the library a client
links against) exports it, including re-exports (trie flag 0x8); with --lib-only the check uses the Darling
library that has the same install name as the cache exporter, and its own re-exports.
Prints per symbol "OK <lib>" or "MISSING", then counts.
"""
import collections
import subprocess
import sys

EXPORTS, ROOT, NEEDS = sys.argv[1], sys.argv[2], sys.argv[3]
LIB_ONLY = "--lib-only" in sys.argv
LIBSYSTEM = f"{ROOT}/src/external/libsystem/libSystem.B.dylib"
FILES = {}  # install name -> path, built from the dylibs' own LC_ID_DYLIB found under src/


def run(path):
    p = subprocess.run([EXPORTS, path], capture_output=True, text=True)
    ids, re, ex = [], [], {}
    for line in p.stdout.splitlines():
        f = line.split("\t")
        if f[0] == "I":
            ids.append(f[1])
        elif f[0] == "R":
            re.append(f[1])
        elif f[0] == "E":
            ex[f[1]] = f[3]
    return ids, re, ex


def index_build():
    out = subprocess.run(["find", f"{ROOT}/src", "-name", "*.dylib", "-type", "f", "-not", "-path", "*/CMakeFiles/*", "-not", "-name", "*firstpass*"], capture_output=True, text=True).stdout.split()
    for path in sorted(out):
        ids, _, _ = run(path)
        if ids and ids[0] not in FILES:
            FILES[ids[0]] = path


index_build()
CACHE = {}


def exports_of(install):
    if install not in CACHE:
        path = FILES.get(install)
        CACHE[install] = (run(path) if path else ([], [], {}))
    return CACHE[install]


def closure(install, seen=None):
    seen = seen if seen is not None else set()
    if install in seen:
        return seen
    seen.add(install)
    for r in exports_of(install)[1]:
        closure(r, seen)
    return seen


root = closure("/usr/lib/libSystem.B.dylib")
providers = collections.defaultdict(list)  # symbol -> install names exporting it (within the libSystem closure)
for inst in sorted(root):
    for name in exports_of(inst)[2]:
        providers[name].append(inst)
missing_libs = sorted(i for i in root if i not in FILES)
print(f"# Darling libSystem.B closure: {len(root)} install names, {len(root) - len(missing_libs)} found in the build tree, {len(providers)} distinct exported symbols")
if missing_libs:
    print("# not found in build tree: " + " ".join(missing_libs))
tot = miss = 0
by_exporter = collections.defaultdict(lambda: [0, 0])
for line in open(NEEDS):
    f = line.rstrip("\n").split("\t")
    if len(f) < 2 or not f[0].startswith("/"):
        continue
    exporter, sym = f[0], f[1]
    tot += 1
    if LIB_ONLY:
        have = [exporter] if sym in exports_of(exporter)[2] else []
        # re-exports of that library count too
        for r in closure(exporter) - {exporter}:
            if sym in exports_of(r)[2]:
                have.append(r)
    else:
        have = providers.get(sym, [])
    by_exporter[exporter][0] += 1
    if have:
        print(f"OK\t{exporter}\t{sym}\t{have[0]}")
    else:
        miss += 1
        by_exporter[exporter][1] += 1
        print(f"MISSING\t{exporter}\t{sym}")
print(f"# needed {tot}, missing {miss}")
for e, (t, m) in sorted(by_exporter.items()):
    print(f"# exporter {e}: needed {t}, missing {m}")
