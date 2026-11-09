#!/usr/bin/env python3 -I
"""Mutation probes for the pure scanner parts: apply one edit to a scratch copy, build and run one test,
and require that the test fails. Never edits the tree. Usage: mutate.py <scratch dir>  (run under capped_run.py)."""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
SCRATCH = sys.argv[1]
CC = ["gcc", "-O1", "-g", "-Wall", "-Wextra", "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]

# (header, old text, new text, test)
MUTANTS = [
    ("a64.h", "x == 0xD4001001u", "x == 0xD4001002u", "test_a64"),
    ("a64.h", "(nx & 0xFFC00000u) == 0x92400000u && (nx & 31) == rt", "(nx & 0xFFC00000u) == 0x92400000u && 0 && (nx & 31) == rt", "test_a64"),
    ("a64.h", "#define A64_COMMPAGE_END 0x1000000000ULL", "#define A64_COMMPAGE_END 0xFFFFFC050ULL", "test_a64"),
    ("a64.h", "#define A64_WINDOW 24", "#define A64_WINDOW 200", "test_a64"),
    ("a64.h", "(x & 0xFC000000u) == 0x94000000u || (x & 0xFE000000u)", "(x & 0xFC000000u) == 0x94000001u || (x & 0xFE000000u)", "test_a64"),
    ("a64.h", "*imm = (int64_t)((x >> 10) & 0xFFF) << scale;", "*imm = (int64_t)((x >> 10) & 0xFFF);", "test_a64"),
    ("a64.h", "                a64_kill_reg(s, (int)rd);\n                if (s->mv[rd].valid", "                if (s->mv[rd].valid", "test_a64"),
    ("a64.h", "if (s->pg[r].valid && a64_writes(x, (int)r)) killmask |= 1u << r;", "if (0) killmask |= 1u << r;", "test_a64"),
    ("a64.h", "                        s->pg[x & 31].valid = 0;\n                        continue;", "                        s->pg[x & 31].valid = 0;", "test_a64"),
    ("a64.h", "if (opc == 2) { s->mv[rd].valid = 1; s->mv[rd].val = (imm << sh) & mask;", "if (opc == 2) { s->mv[rd].valid = 1; s->mv[rd].val = (imm << sh) & 0xFFFFFFFFULL;", "test_a64"),
    ("a64.h", "if (!(s->mv[rd].valid && s->idx - s->mv[rd].at <= 8)) { s->mv[rd].valid = 1; s->mv[rd].val = 0; s->mv[rd].cov = 0; }", "if (!s->mv[rd].valid) { s->mv[rd].valid = 1; s->mv[rd].val = 0; s->mv[rd].cov = 0; }", "test_a64"),
    ("trie.h", "depth > TRIE_MAX_DEPTH", "depth > 100000", "test_trie"),
    ("trie.h", "    if (term > s->size - pos) return -1;\n", "", "test_trie"),
    ("trie.h", "if (child >= s->size || child <= off) return -1;", "if (child >= s->size) return -1;", "test_trie"),
    ("trie.h", "if (flags & TRIE_FLAGS_REEXPORT) {", "if (flags & TRIE_FLAGS_STUB_AND_RESOLVER) {", "test_trie"),
    ("trie.h", "if (e >= children) return -1;", "if (0) return -1;", "test_trie"),
    ("patch_v4_check.h", "e->imageExportIndex - p->exportsStartIndex >= p->exportsCount) pv4_fail(r, PV4_E_EXPORT_INDEX, k);", "e->imageExportIndex - p->exportsStartIndex > p->exportsCount) pv4_fail(r, PV4_E_EXPORT_INDEX, k);", "test_patch_v4"),
    ("patch_v4_check.h", "env->image_addr[c->clientDylibIndex] + v->locations[l].dylibOffsetOfUse)) pv4_fail", "env->cache_base + v->locations[l].dylibOffsetOfUse)) pv4_fail", "test_patch_v4"),
    ("patch_v4_check.h", "env->cache_base + (((uint64_t)g->cacheOffsetHi << 32) | g->cacheOffsetLo))) pv4_fail", "env->cache_base + g->cacheOffsetLo)) pv4_fail", "test_patch_v4"),
    ("patch_v4_check.h", "if (p->clientsStartIndex != next_client ||", "if (0 ||", "test_patch_v4"),
    ("patch_v4_check.h", "if (c->clientDylibIndex >= env->nimages) pv4_fail", "if (0) pv4_fail", "test_patch_v4"),
    ("patch_v4_check.h", "!memchr(v->names + off, 0, h->exportNamesSize - off)", "0", "test_patch_v4"),
    ("patch_v4_check.h", "if (g->reserved) pv4_fail", "if (0) pv4_fail", "test_patch_v4"),
    ("patch_v4_check.h", "if (a[i].addr % 4)", "if (0)", "test_patch_v4"),
    ("patch_v4.h", "d.usesAddressDiversity = (f >> 14) & 1;", "d.usesAddressDiversity = (f >> 13) & 1;", "test_patch_v4"),
    ("patch_v4.h", "d.addend = (f >> 9) & 0x7f;", "d.addend = (f >> 9) & 0x1f;", "test_patch_v4"),
]


def main():
    killed = survived = 0
    for hdr, old, new, test in MUTANTS:
        work = os.path.join(SCRATCH, "mut")
        shutil.rmtree(work, ignore_errors=True)
        shutil.copytree(SRC, work, ignore=shutil.ignore_patterns("tests", "*.o", "m3_scan", "m3_exports"))
        shutil.copytree(HERE, os.path.join(work, "tests"), ignore=shutil.ignore_patterns("test_a64", "test_trie", "test_patch_v4"))
        path = os.path.join(work, hdr)
        text = open(path).read()
        if text.count(old) != 1:
            sys.exit(f"mutant text not unique ({text.count(old)}x) in {hdr}: {old[:60]!r}")
        open(path, "w").write(text.replace(old, new))
        exe = os.path.join(work, "tests", test)
        cc = subprocess.run(CC + ["-o", exe, os.path.join(work, "tests", test + ".c")], capture_output=True, text=True)
        if cc.returncode:
            print(f"KILLED (does not compile) {hdr}: {old[:50]!r}")
            killed += 1
            continue
        run = subprocess.run([exe], capture_output=True, text=True)
        if run.returncode:
            killed += 1
            print(f"KILLED {hdr}: {old[:60]!r}")
        else:
            survived += 1
            print(f"SURVIVED {hdr}: {old[:60]!r} -> {new[:40]!r}")
    print(f"mutants: {killed} killed, {survived} survived")
    sys.exit(1 if survived else 0)


main()
