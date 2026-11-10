#!/usr/bin/env python3
"""EXPERIMENT (local): build l4_plain.dylib, a plain arm64 dylib importing std::set_terminate and std::get_terminate from
the cache's libc++ (link-only stub), for the reverse-adapter checks. Needs LD64 and SDKROOT like build_l4.py.
  build_plain_dylib.py --out DIR"""
import argparse, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.dont_write_bytecode = True
sys.path[:0] = [HERE, os.path.join(ROOT, "abi"), os.path.join(ROOT, "h0"), ROOT]
import build_abi, build_h0, gen_stub  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--out", required=True)
a = ap.parse_args()
os.makedirs(a.out, exist_ok=True)
sdk = build_abi.sdk_libs()
sym = os.path.join(a.out, "symbols-libcxx-plain.txt")
gen_stub.write_symbols(["_ZSt13set_terminatePFvvE", "_ZSt13get_terminatev"], sym, "C++ names l4_plain.c imports")
stub = build_h0.build_stub("libc++", a.out, sym, build_abi.build_plain)
out = os.path.join(a.out, "l4_plain.dylib")
build_abi.build_plain([os.path.join(HERE, "l4_plain.c")], out, kind="dylib",
                      cflags=["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-O0", "-isysroot", sdk, "-Wno-incompatible-sysroot"],
                      install_name="/usr/lib/l4_plain.dylib", libs=[stub, "-lSystem"], ld_args=["-syslibroot", sdk])
print("OK", out)
