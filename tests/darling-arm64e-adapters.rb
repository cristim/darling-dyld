# The arm64e adapter table and thunks of dyld3/DarlingArm64eAdapters.cpp, on this host (arm64 Linux with pointer
# authentication, SKIP otherwise): table validation, the table against the Darwin prototypes (independent spec below),
# every thunk's bytes against llvm-mc, a native run with real PAC instructions (strip of signed, unsigned, NULL, -1, 1 and
# a garbage high-bit pointer; re-sign of signal() and Block_copy results; blocks and sigaction), and mutation probes: each
# mutant of the source must make this test fail.
# Env: REQUIRED_SYMBOLS=<file with one Mach-O symbol per line, e.g. the callback-taking imports of the T0 facts scan>:
# each must have a row, supported or explicitly unsupported (a missing row is a failure).
# Usage: ruby tests/darling-arm64e-adapters.rb [checkout]
require 'tmpdir'
require 'open3'
require 'fileutils'
require 'rbconfig'

root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
HWCAP_PACA = 1 << 30
host_hwcap = File.binread('/proc/self/auxv').unpack('Q*').each_slice(2).find { |type, _| type == 16 }&.last.to_i
unless RbConfig::CONFIG['host_cpu'] =~ /aarch64|arm64/ && (host_hwcap & HWCAP_PACA) != 0 && system('clang++', '--version', out: File::NULL, err: File::NULL)
  puts 'SKIP darling-arm64e-adapters: needs an arm64 Linux host with pointer authentication and clang++'
  exit 0
end
HAVE_MC = system('llvm-mc', '--version', out: File::NULL, err: File::NULL)

$failures = 0
def check(desc, ok, detail = nil)
  if ok
    puts "PASS #{desc}"
  else
    $failures += 1
    puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}"
  end
end

# What the table must say, written from the Darwin prototypes and the L2 probe (tests/arm64e-link/abi), not from the table:
# symbol => [strip mask, block arg + 1, struct arg + 1, return fix (0 none, 1 sign function IA0, 2 re-sign block invoke), argc, status (0 probed, 1 shape only, 2 unsupported)]
SPEC = {
  '___cxa_atexit' => [0x1, 0, 0, 0, 3, 0],                 # __cxa_atexit(void (*f)(void*), void* arg, void* dso)
  '_atexit' => [0x1, 0, 0, 0, 1, 0],                       # atexit(void (*f)(void))
  '_pthread_key_create' => [0x2, 0, 0, 0, 2, 0],           # (pthread_key_t*, void (*destructor)(void*))
  '_pthread_create' => [0x4, 0, 0, 0, 4, 0],               # (pthread_t*, const pthread_attr_t*, void* (*start)(void*), void* arg)
  '_pthread_once' => [0x2, 0, 0, 0, 2, 0],                 # (pthread_once_t*, void (*init)(void))
  '_qsort' => [0x8, 0, 0, 0, 4, 0],                        # (base, nel, width, int (*compar)(const void*, const void*))
  '__dyld_register_func_for_add_image' => [0x1, 0, 0, 0, 1, 0],
  '_dispatch_async' => [0x0, 2, 0, 0, 2, 0],               # (queue, block)
  '_dispatch_once' => [0x0, 2, 0, 0, 2, 0],                # (predicate*, block)
  '_sigaction' => [0x0, 0, 2, 0, 3, 0],                    # (sig, const struct sigaction* act, struct sigaction* oact)
  '_signal' => [0x2, 0, 0, 1, 2, 0],                       # sig_t signal(int, sig_t)
  '__Block_copy' => [0x0, 0, 0, 2, 1, 0],                  # void* _Block_copy(const void*)
  '__tlv_atexit' => [0x1, 0, 0, 0, 2, 1],                  # (void (*termFunc)(void*), void* objAddr)
  '__dyld_register_func_for_remove_image' => [0x1, 0, 0, 0, 1, 1],
  '_dispatch_block_create' => [0, 0, 0, 0, 0, 2],
  '_atexit_b' => [0, 0, 0, 0, 0, 2],
  '_qsort_b' => [0, 0, 0, 0, 0, 2],
}.freeze
# the symbols the L4 set and the L2 probe import (plan shared-cache-m3-l4.md Q1)
L4_AND_L2 = %w[___cxa_atexit _atexit _pthread_key_create _pthread_create _pthread_once __tlv_atexit _qsort _dispatch_async
               _dispatch_once __dyld_register_func_for_add_image _signal _sigaction __Block_copy].freeze

def extract_sign_pointer(source)
  text = source[/^#if !__has_feature\(ptrauth_calls\)[^\n]*\n__attribute__\(\(target\("arch=armv8\.3-a"\)\)\)\n#endif\nuint64_t MachOLoaded::ChainedFixupPointerOnDisk::Arm64e::signPointer\(uint64_t unsignedAddr.*?^\}\n/m]
  abort 'signPointer not found in dyld3/MachOLoaded.cpp' unless text
  text
end

SHIM_LOADED = <<~H
  #pragma once
  #include <stdint.h>
  namespace dyld3 { struct MachOLoaded { struct ChainedFixupPointerOnDisk { struct Arm64e {
    static uint64_t signPointer(uint64_t unsignedAddr, void* loc, bool addrDiv, uint16_t diversity, uint8_t key);
  }; }; }; }
H
SHIM_MACHINE = <<~H
  #pragma once
  #include <stdint.h>
  typedef int cpu_subtype_t;
  #define CPU_SUBTYPE_MASK 0xff000000
  #define CPU_SUBTYPE_ARM64E ((cpu_subtype_t) 2)
H

def build(root, dir, name, adapters_text: nil)
  work = File.join(dir, name)
  FileUtils.mkdir_p(File.join(work, 'mach'))
  File.write(File.join(work, 'MachOLoaded.h'), SHIM_LOADED)
  File.write(File.join(work, 'mach', 'machine.h'), SHIM_MACHINE)
  FileUtils.cp(File.join(root, 'dyld3/DarlingArm64eAdapters.h'), work)
  File.write(File.join(work, 'DarlingArm64eAdapters.cpp'), adapters_text || File.read(File.join(root, 'dyld3/DarlingArm64eAdapters.cpp')))
  File.write(File.join(work, 'sign.cpp'), "#include <stdint.h>\n#include <assert.h>\n#include \"MachOLoaded.h\"\nusing namespace dyld3;\n#{extract_sign_pointer(File.read(File.join(root, 'dyld3/MachOLoaded.cpp')))}")
  exe = File.join(work, 'host')
  _o, e, st = Open3.capture3('clang++', '-std=c++17', '-O1', '-g', '-Wall', '-Wno-unused-function', '-I', work, File.join(root, 'tests/darling-arm64e-adapters-host.cpp'),
                             File.join(work, 'DarlingArm64eAdapters.cpp'), File.join(work, 'sign.cpp'), '-o', exe)
  [st.success? ? exe : nil, e]
end

def run(exe, *args)
  o, e, st = Open3.capture3(exe, *args)
  [o + e, st]
end

Dir.mktmpdir('darling-arm64e-adapters-') do |dir|
  exe, err = build(root, dir, 'real')
  check 'the module and the native driver compile', !exe.nil?, err[0, 600]
  abort "#{$failures} failures" unless exe

  # ---------------------------------------------------------------- the table
  out, = run(exe, 'rows')
  rows = out.lines.map { |l| l.split }.select { |f| f[0] == 'ROW' }.to_h { |f| [f[1], f[2..].map(&:to_i)] }
  check 'the table has exactly the rows of the spec', rows.keys.sort == SPEC.keys.sort, "extra #{(rows.keys - SPEC.keys).inspect} missing #{(SPEC.keys - rows.keys).inspect}"
  SPEC.each { |sym, want| check "row #{sym} matches the Darwin prototype", rows[sym] == want, "#{rows[sym].inspect} want #{want.inspect}" if rows[sym] }
  check 'every symbol of the L4 set and the L2 probe has a row', (L4_AND_L2 - rows.keys).empty?, (L4_AND_L2 - rows.keys).inspect
  if (file = ENV['REQUIRED_SYMBOLS'])
    required = File.readlines(file).map(&:strip).reject { |l| l.empty? || l.start_with?('#') }
    check "every symbol of #{File.basename(file)} has a row (#{required.size} symbols)", (required - rows.keys).empty?, (required - rows.keys).inspect
  end

  # ---------------------------------------------------------------- the thunk bytes against an assembler
  def mc_words(listing)
    o, e, st = Open3.capture3('llvm-mc', '-triple=aarch64', '-mattr=+pauth', '-show-encoding', stdin_data: listing)
    return nil unless st.success?
    o.lines.grep(/encoding:/).map { |l| l[/encoding: \[(.*)\]/, 1].scan(/0x(\h\h)/).flatten.map { |b| b.to_i(16) }.pack('C*').unpack1('V') }
  rescue StandardError
    nil
  end
  if HAVE_MC
    bad = []
    (1..255).each do |mask|
      regs = (0..7).select { |i| mask[i] == 1 }
      listing = (regs.size.odd? ? ["nop"] : []) + regs.map { |i| "xpaci x#{i}" } + ['ldr x16, #8', 'br x16']
      want = mc_words(listing.join("\n"))
      got = run(exe, 'strip-thunk', mask.to_s)[0].split.map { |w| w.to_i(16) }
      bad << mask unless want && got == want + [0x55667788, 0x11223344]
    end
    check 'strip thunks of all 255 masks are what llvm-mc assembles (xpaci per register, ldr x16, br x16, literal)', bad.empty?, bad.first(5).inspect
    %w[_dispatch_async _dispatch_once _sigaction _signal __Block_copy].each do |sym|
      o = run(exe, 'call-thunk', sym)[0].lines
      head = o.shift.split
      row, helper = head[1].to_i(16), head[3].to_i(16)
      got = o.map { |w| w.to_i(16) }
      listing = ['stp x29, x30, [sp, #-80]!', 'mov x29, sp', 'stp x0, x1, [sp, #16]', 'stp x2, x3, [sp, #32]', 'stp x4, x5, [sp, #48]', 'stp x6, x7, [sp, #64]',
                 'add x0, sp, #16', 'ldr x1, #28', 'ldr x2, #32', 'ldr x16, #36', 'blr x16', 'ldp x29, x30, [sp], #80', 'ret', 'nop']
      want = mc_words(listing.join("\n"))
      lit = ->(v) { [v & 0xffffffff, v >> 32] }
      check "call thunk of #{sym} is what llvm-mc assembles", want && got == want + lit[row] + lit[0x1122334455667788] + lit[helper], got.map { |w| format('%08x', w) }.join(' ')[0, 200]
    end
  else
    puts 'SKIP thunk bytes: llvm-mc not found'
  end

  # ---------------------------------------------------------------- the native run
  out, st = run(exe)
  out.lines.grep(/^FAIL/).first(12).each { |l| puts l }
  summary = out.lines.grep(/^(PASS|FAIL) \d+ checks/).last.to_s.strip
  check "native run on real PAC instructions: #{summary}", st.success? && summary.start_with?('PASS')
  checks_run = summary[/\d+/].to_i
  check 'the native run did a meaningful number of checks', checks_run >= 300, checks_run

  # the module also compiles where there are no arm64e importers
  _o, e, st = Open3.capture3('clang++', '--target=x86_64-linux-gnu', '-std=c++17', '-fsyntax-only', '-I', File.join(dir, 'real'), File.join(dir, 'real/DarlingArm64eAdapters.cpp'))
  check 'the module compiles for x86_64 as an identity', st.success?, e[0, 300]

  # ---------------------------------------------------------------- mutation probes: each must make the test fail
  source = File.read(File.join(root, 'dyld3/DarlingArm64eAdapters.cpp'))
  mutants = {
    'a strip thunk names the wrong register' => ['0xDAC143E0 | i', '0xDAC143E0 | (i + 1)'],
    'a strip thunk loses its branch' => ['words[n++] = 0xD61F0200;', 'words[n++] = kNop;'],
    'a strip thunk loses its padding nop' => ['if ( (__builtin_popcount(stripMask) & 1) != 0 )', 'if ( false )'],
    'the strip is applied to the returned value instead of signing it' => ['result = signFunctionIA0(result);', 'result = stripCode(result);'],
    'the call thunk ignores the strip mask' => ['a[i] = stripCode(a[i]);', 'a[i] = a[i];'],
    'signal return values -1 are signed' => ['|| (pointer == ~0ULL)', ''],
    'signal return values 0 and 1 are signed' => ['(pointer == 0) || (pointer == 1) ||', ''],
    'a stack block does not get its signature back' => ['*restoreSlot = restoreValue;', '(void)restoreValue;'],
    'a stack block is never restored (slot not recorded)' => ['restoreSlot = &block->invoke;', 'restoreSlot = nullptr;'],
    'a global block is stripped in place' => ['a[row->blockArg - 1] = (uint64_t)mirrorOfGlobalBlock(block);', 'block->invoke = (void*)stripCode((uint64_t)block->invoke);'],
    'a global block mirror is not stripped' => ['copy->invoke = (void*)stripCode((uint64_t)block->invoke);', ''],
    'Block_copy re-signs without address diversity' => ['&block->invoke, true, 0, 0)', 'nullptr, false, 0, 0)'],
    'Block_copy re-signs a global block in place' => ['if ( (block->flags & kBlockIsGlobal) == 0 )', 'if ( true )'],
    'Block_copy does not strip before it signs' => ['signPointer(stripCode((uint64_t)block->invoke), &block->invoke', 'signPointer((uint64_t)block->invoke, &block->invoke'],
    'sigaction hands the caller\'s struct to the callee' => ['a[row->structArg - 1] = (uint64_t)structCopy;', ''],
    'sigaction does not strip the handler' => ['structCopy[0] = stripCode(structCopy[0]);', ''],
    'a thunk is made again for the same row and target' => ['(sThunks[i].real == real) )', '(sThunks[i].real == real) && false )'],
    'an unsupported row is bound as if supported' => [/if \( row->status == AdapterStatus::Unsupported \) \{(\s+dyld::warn)/, 'if ( false ) {\1'],
    'an arm64e target is thunked' => ['if ( !sEnabled || targetIsArm64e )', 'if ( !sEnabled )'],
    'the kill switch does nothing' => ['if ( !sEnabled || targetIsArm64e )', 'if ( targetIsArm64e )'],
    'the row of _atexit strips the wrong argument' => [/("_atexit",\s*)0x1,/, '\10x2,'],
    'the row of _pthread_create strips the wrong argument' => [/("_pthread_create",\s*)0x4,/, '\10x2,'],
    'the row of _signal is missing its return fix' => ['0x2, 0, 0, ReturnFix::SignFunctionIA0,', '0x2, 0, 0, ReturnFix::None,'],
    'the row of _qsort is dropped' => [/^\t\{ "_qsort",.*\n/, ''],
    'the validator accepts a nine-argument row' => ['(r.argCount > 8)', '(r.argCount > 9)'],
    'the validator accepts a duplicate symbol' => ['return "a symbol has two rows";', ''],
  }
  killed = 0
  mutants.each_with_index do |(desc, (from, to)), i|
    unless source.scan(from).size == 1
      check "mutant applies: #{desc}", false, "#{source.scan(from).size} matches"
      next
    end
    mutated = from.is_a?(Regexp) ? source.sub(from, to) : source.sub(from) { to }
    mexe, merr = build(root, dir, "mutant#{i}", adapters_text: mutated)
    dead = mexe.nil? || begin
      mout, mst = run(mexe)
      !mst.success? || mout =~ /^FAIL/
    end
    # a mutated table row is caught by the comparison with the spec, which reads the rows output
    spec_dead = !mexe.nil? && run(mexe, 'rows')[0].lines.grep(/^ROW/).map { |l| l.split }.to_h { |f| [f[1], f[2..].map(&:to_i)] } != SPEC
    bytes_dead = false
    if mexe && HAVE_MC && !dead
      # a thunk-shape mutant that the native run does not see is still caught by the assembler comparison
      bad = (1..255).any? do |mask|
        regs = (0..7).select { |b| mask[b] == 1 }
        want = mc_words(((regs.size.odd? ? ['nop'] : []) + regs.map { |b| "xpaci x#{b}" } + ['ldr x16, #8', 'br x16']).join("\n"))
        run(mexe, 'strip-thunk', mask.to_s)[0].split.map { |w| w.to_i(16) } != want + [0x55667788, 0x11223344]
      end
      bytes_dead = bad
    end
    killed += 1 if dead || spec_dead || bytes_dead
    check "mutation probe killed: #{desc}", dead || spec_dead || bytes_dead, merr[0, 200]
  end
  puts "probes killed #{killed}/#{mutants.size}"
end

puts($failures.zero? ? 'ALL PASS' : "#{$failures} FAILURES")
exit($failures.zero? ? 0 : 1)
