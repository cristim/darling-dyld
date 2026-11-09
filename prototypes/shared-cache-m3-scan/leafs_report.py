#!/usr/bin/env python3 -I
"""H0 leaf candidates: per image the dependency list, svc/TSD/commpage counts (window outputs) and import pairs (imports mode).
Usage: leafs_report.py <deps.tsv> <window dir> <imports-leafs.txt> <install name>...
deps.tsv: one image per line, "install name<TAB>dependency<TAB>..." (written by the M0b scanner). Facts only."""
import glob
import sys

deps_f, win, imports_f, paths = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
deps = {}
for line in open(deps_f):
    f = line.rstrip("\n").split("\t")
    deps[f[0]] = f[1:]
rows = {}
for fn in glob.glob(f"{win}/*.txt"):
    for line in open(fn):
        f = line.rstrip("\n").split("\t")
        if f[0] == "P" and f[1] in paths:
            rows[f[1]] = dict(svc=int(f[3]), tsd=int(f[4]) + int(f[5]), sites=int(f[6]), lits=int(f[8]))
        elif f[0] in ("W", "O", "Q") and f[1] in paths:
            rows.setdefault(f[1], {}).setdefault("extra", []).append(f[0])
imps = {}
for line in open(imports_f):
    f = line.rstrip("\n").split("\t")
    if f[0] == "S":
        imps[f[1]] = (f[3].split()[1], f[4].split()[1])
print("image\tdeps\tsvc\ttsd\tcommpage_sites\tcommpage_literals\timport_pairs\tfrom_libSystem_family\tdependency list")
for p in paths:
    r = rows.get(p, {})
    d = deps.get(p, [])
    i = imps.get(p, ("?", "?"))
    print(f"{p}\t{len(d)}\t{r.get('svc', '?')}\t{r.get('tsd', '?')}\t{r.get('sites', '?')}\t{r.get('lits', '?')}\t{i[0]}\t{i[1]}\t{' '.join(d)}")
