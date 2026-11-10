# The opposite-direction adapters (a PLAIN importer binding an export of an arm64e image) of dyld3/DarlingArm64eAdapters.cpp on
# this host (arm64 Linux with pointer authentication, SKIP otherwise): the table against an independent reading of the mangled
# names, a native run with real PAC instructions (signing, stripping, NULL, data, round trips, thunk page), and mutation probes:
# each mutant of the source must make this test fail. EXPERIMENT (local branch exp/l4-reverse-adapters).
# Usage: ruby tests/darling-arm64e-reverse-adapters.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
require_relative 'darling-arm64e-adapters-support'
unless AdapterSupport.pac_host?
  puts 'SKIP darling-arm64e-reverse-adapters: needs an arm64 Linux host with pointer authentication and clang++'
  exit 0
end
$failures = 0
def check(desc, ok, detail = nil)
  if ok then puts "PASS #{desc}" else $failures += 1; puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}" end
end
driver = File.join(root, 'tests/darling-arm64e-reverse-adapters-host.cpp')
Dir.mktmpdir('rev-adapters') do |dir|
  exe, err = AdapterSupport.build(root, dir, 'base', driver)
  check('the driver builds', !exe.nil?, err)
  abort "build failed:\n#{err}" unless exe
  out, st = AdapterSupport.run(exe)
  check('the native checks pass', st.success?, out)
  puts out.lines.last

  # The table against the mangled names (independent of the table): a name with PF has one masked argument per function
  # pointer parameter, a member function counts `this` as argument 0, the handler getters strip, set_* sign and strip.
  rows, = AdapterSupport.run(exe, 'rows')
  table = rows.lines.map { |l| s, m, st2, c, status = l.split; [s, [m.to_i(16), st2 == '1', c.to_i, status.to_i]] }.to_h
  cache = (ENV['CACHE_EXPORTS'] ? File.readlines(ENV['CACHE_EXPORTS'], chomp: true) : [])
  expected_pf = cache.select { |n| n.include?('PF') && !n.include?('money_get') }
  check('every cache export with a function-pointer parameter has a supported row (skipped without the export list)',
        cache.empty? || expected_pf.all? { |n| table.key?(n) && table[n][3] != 3 }, expected_pf.reject { |n| table[n] }.inspect)
  table.each do |sym, (mask, strip, argc, status)|
    next if status == 3
    pf = sym.scan(/PF/).size
    member = sym.start_with?('__ZNSt3__1') && !sym.include?('__call_once')
    is_getter = sym =~ /get_(terminate|unexpected|new_handler)v\z/
    if is_getter
      check("#{sym}: a getter authenticates the result and signs nothing", strip && mask == 0)
    elsif sym =~ /set_(terminate|unexpected|new_handler)P/
      check("#{sym}: sets sign argument 0 and authenticate the old handler", mask == 1 && strip)
    elsif sym == '___cxa_throw'
      check('___cxa_throw signs the destructor (argument 2)', mask == 4 && !strip)
    else
      check("#{sym}: #{pf} function pointer parameter(s) are signed, no result is a handler", mask.to_s(2).count('1') == pf && !strip && argc >= 1)
    end
    _ = member
  end

  # mutation probes
  adapters = File.read(File.join(root, 'dyld3/DarlingArm64eAdapters.cpp'))
  mutants = {
    'signing is skipped' => ['a[i] = AdapterSign::signPointer(a[i], nullptr, false, 0, 0);', ';'],
    'signing uses the IB key' => ['a[i] = AdapterSign::signPointer(a[i], nullptr, false, 0, 0);', 'a[i] = AdapterSign::signPointer(a[i], nullptr, false, 0, 1);'],
    'signing uses a non-zero discriminator' => ['a[i] = AdapterSign::signPointer(a[i], nullptr, false, 0, 0);', 'a[i] = AdapterSign::signPointer(a[i], nullptr, false, 1, 0);'],
    'the entry check is removed' => ['if ( ((isEntry != nullptr) && isEntry(a[i])) || wasHandedBack(a[i]) )', 'if ( true )'],
    'the entry check is replaced by the handed-back ring only' => ['((isEntry != nullptr) && isEntry(a[i])) || wasHandedBack(a[i])', 'wasHandedBack(a[i])'],
    'the handed-back ring is removed' => ['((isEntry != nullptr) && isEntry(a[i])) || wasHandedBack(a[i])', '((isEntry != nullptr) && isEntry(a[i]))'],
    'a missing predicate signs' => ['((isEntry != nullptr) && isEntry(a[i]))', '((isEntry == nullptr) || isEntry(a[i]))'],
    # (removing the NULL skip is an equivalent mutant: signPointer returns 0 for 0)
    'the returned handler is stripped instead of authenticated' => ['const uint64_t authenticatedResult = authenticateIA(result, 0);', 'const uint64_t authenticatedResult = stripCode(result);'],
    'the returned handler is authenticated with a modifier' => ['const uint64_t authenticatedResult = authenticateIA(result, 0);', 'const uint64_t authenticatedResult = authenticateIA(result, 1);'],
    'a failed authentication is ignored' => ['\t\tif ( !authenticated(authenticatedResult) ) {', '\t\tif ( false ) {'],
    'a failed authentication is stripped and returned' => ['__builtin_trap();\n\t\t}\n\t\trecordHandedBack(authenticatedResult);\n\t\tresult = authenticatedResult;', 'result = stripCode(result);\n\t\t}\n\t\trecordHandedBack(authenticatedResult);\n\t\tresult = stripCode(result);'],
    'special values are authenticated' => ['if ( row->authReturn && !isSpecialHandler(result) )', 'if ( row->authReturn )'],
    'the mask bit is read from the wrong argument' => ["if ( ((row->signMask >> i) & 1) == 0 )\n\t\t\tcontinue;\n\t\tif ( a[i] == 0 )", "if ( ((row->signMask >> (i + 1)) & 1) == 0 )\n\t\t\tcontinue;\n\t\tif ( a[i] == 0 )"],
    'a plain exporter is adapted' => ["if ( (sMode == AdapterMode::Off) || !targetIsArm64e )\n\t\treturn target;\n\tconst ReverseRow* row", "if ( (sMode == AdapterMode::Off) )\n\t\treturn target;\n\tconst ReverseRow* row"],
    'a function start matches any later offset' => ['if ( address == offset )\n\t\t\treturn true;', 'if ( address >= offset )\n\t\t\treturn true;'],
    'the terminator is ignored' => ['if ( delta == 0 )\n\t\t\tbreak;', ';'],
    'the ULEB shift is unbounded' => ['(shift > 63)', '(false)'],
  }
  mutants = mutants.transform_values { |pair| pair.map { |t| t.gsub('\\t', "\t").gsub('\\n', "\n") } }
  mutants.each do |name, (from, to)|
    unless adapters.include?(from)
      check("mutant #{name}: the source text is there to mutate", false)
      next
    end
    mexe, merr = AdapterSupport.build(root, dir, 'mutant', driver, adapters_text: adapters.sub(from) { to })
    if mexe.nil?
      check("mutant #{name} is caught (it did not build)", true, merr[0, 120])
      next
    end
    _o, mst = AdapterSupport.run(mexe)
    check("mutant #{name} is caught", !mst.success?)
  end
end
puts($failures.zero? ? 'ALL PASS' : "#{$failures} FAILED")
exit($failures.zero? ? 0 : 1)
