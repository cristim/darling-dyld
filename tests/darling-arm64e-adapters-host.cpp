// Native driver of tests/darling-arm64e-adapters.rb: the real dyld3/DarlingArm64eAdapters.cpp built for this arm64
// host, with MachOLoaded.h, mach/machine.h and dyld::warn stubbed and the real signPointer extracted from
// dyld3/MachOLoaded.cpp. The expectations use the PAC instructions directly (pacia, autia, xpaci), not the module's
// own helpers. Modes: no argument runs the checks; `rows`, `strip-thunk MASK` and `call-thunk SYMBOL` print what the
// ruby side compares with an assembler.
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include <sys/mman.h>

#include "DarlingArm64eAdapters.h"

using namespace dyld3::darling;

static std::string gWarnings;
namespace dyld {
void warn(const char* format, ...)
{
	char line[512];
	va_list list;
	va_start(list, format);
	vsnprintf(line, sizeof(line), format, list);
	va_end(list);
	gWarnings += line;
}
}

static int gFailures, gChecks;
#define CHECK(cond, ...) do { ++gChecks; if (!(cond)) { ++gFailures; printf("FAIL %s:%d %s: ", __FILE__, __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)

// ---------------------------------------------------------------- independent PAC oracle
__attribute__((target("arch=armv8.3-a"))) static uint64_t oracleSign(uint64_t p, uint64_t modifier) { asm("pacia %0, %1" : "+r"(p) : "r"(modifier)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t oracleAuth(uint64_t p, uint64_t modifier) { asm("autia %0, %1" : "+r"(p) : "r"(modifier)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t oracleStrip(uint64_t p) { asm("xpaci %0" : "+r"(p)); return p; }

// ---------------------------------------------------------------- a fake plain callee that records what it got
static uint64_t gSeen[8];
static int gCalls;
static uint64_t gFakeResult;
static void (*gHook)(const uint64_t* args);
static uint64_t fake8(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
	const uint64_t a[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
	memcpy(gSeen, a, sizeof(a));
	++gCalls;
	if ( gHook )
		gHook(a);
	return gFakeResult;
}
typedef uint64_t (*Fn8)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static const uint64_t kSentinel[8] = { 0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444,
									   0x5555555555555555, 0x6666666666666666, 0x7777777777777777, 0x0888888888888888 };

static uint64_t codeAddress(int n) { return 0x0000000100003000ULL + 0x40 * n; }

static Fn8 thunkFor(const char* symbol)
{
	const uint64_t t = adaptedTarget(symbol, (uint64_t)&fake8, false);
	CHECK(t != (uint64_t)&fake8, "%s was not adapted", symbol);
	return (Fn8)t;
}

struct Block { void* isa; int32_t flags; int32_t reserved; void* invoke; void* descriptor; };
static const int32_t kHeap = 1 << 24, kGlobal = 1 << 28;
// A global block's literal lives in read-only memory and carries the signature that the arm64e image's own fixups gave it:
// built in a page that is made read-only, so that a write into it by the module crashes the test.
static const Block* gGlobalBlock;
static void makeGlobalBlock()
{
	Block* page = (Block*)mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	*page = { nullptr, kGlobal, 0, (void*)oracleSign(0x0000000100004000ULL, (uint64_t)&page->invoke), nullptr };
	mprotect(page, 4096, PROT_READ);
	gGlobalBlock = page;
}

static uint64_t gBlockInvokeSeen;
static void snapshotBlock(const uint64_t* a) { const Block* b = (const Block*)a[1]; if (b) { gBlockInvokeSeen = (uint64_t)b->invoke; } }

static void checkPacWorks()
{
	const uint64_t p = codeAddress(1), s = oracleSign(p, 0);
	CHECK(s != p, "this host does not sign (no pointer authentication): the test cannot say anything");
	CHECK(oracleStrip(s) == p, "oracle strip");
	CHECK(oracleAuth(s, 0) == p, "oracle auth");
	CHECK(oracleAuth(s, 1) != p, "oracle auth with the wrong modifier must not give the pointer back");
}

static void checkTable()
{
	size_t n = 0;
	const AdapterRow* rows = adapterRows(&n);
	const char* error = validateAdapterRows(rows, n);
	CHECK(error == nullptr, "built-in table: %s", error ? error : "");
	CHECK(n >= 15, "rows: %zu", n);

	auto bad = [](const AdapterRow r, const char* why) {
		AdapterRow two[2] = { { "_ok", 1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "e" }, r };
		CHECK(validateAdapterRows(two, 2) != nullptr, "a malformed table was accepted: %s", why);
	};
	bad({ "nounderscore", 1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "e" }, "no underscore");
	bad({ "_ok", 1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "e" }, "duplicate");
	bad({ "_a", 1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "" }, "no evidence");
	bad({ "_a", 0, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "e" }, "no action");
	bad({ "_a", 4, 0, 0, ReturnFix::None, 2, AdapterStatus::Probed, "e" }, "mask beyond argCount");
	bad({ "_a", 1, 0, 0, ReturnFix::None, 9, AdapterStatus::Probed, "e" }, "nine arguments");
	bad({ "_a", 1, 0, 0, ReturnFix::None, 0, AdapterStatus::Probed, "e" }, "no argument count");
	bad({ "_a", 0, 3, 0, ReturnFix::None, 2, AdapterStatus::Probed, "e" }, "block argument beyond argCount");
	bad({ "_a", 0, 1, 1, ReturnFix::None, 2, AdapterStatus::Probed, "e" }, "block and struct together");
	bad({ "_a", 1, 1, 0, ReturnFix::None, 2, AdapterStatus::Probed, "e" }, "block argument also stripped");
	bad({ "_a", 1, 0, 0, ReturnFix::None, 1, AdapterStatus::Unsupported, "e" }, "unsupported row with an action");
}

static void checkStripRows()
{
	size_t n = 0;
	const AdapterRow* rows = adapterRows(&n);
	// signed, unsigned, NULL, -1, 1 and a garbage pointer with high bits set, for every argument position of every row
	const uint64_t values[] = { oracleSign(codeAddress(2), 0), codeAddress(3), 0, ~0ULL, 1, 0x9234567812345678ULL, oracleSign(codeAddress(4), 0x1234) };
	int rowsRun = 0;
	for (size_t r = 0; r != n; ++r) {
		const AdapterRow& row = rows[r];
		if ( (row.status == AdapterStatus::Unsupported) || row.blockArg || row.structArg || (row.ret != ReturnFix::None) )
			continue;
		++rowsRun;
		Fn8 t = thunkFor(row.symbol);
		for (uint64_t v : values) {
			uint64_t args[8];
			memcpy(args, kSentinel, sizeof(args));
			for (unsigned i = 0; i != 8; ++i)
				if ( (row.stripMask >> i) & 1 )
					args[i] = v;
			gCalls = 0;
			gFakeResult = 0xabcdef;
			const uint64_t result = t(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
			CHECK(gCalls == 1, "%s: the target was called %d times", row.symbol, gCalls);
			CHECK(result == 0xabcdef, "%s: the result was changed", row.symbol);
			for (unsigned i = 0; i != 8; ++i) {
				const uint64_t want = ((row.stripMask >> i) & 1) ? oracleStrip(v) : kSentinel[i];
				CHECK(gSeen[i] == want, "%s arg %u: value 0x%llx arrived as 0x%llx, want 0x%llx", row.symbol, i, (unsigned long long)args[i], (unsigned long long)gSeen[i], (unsigned long long)want);
			}
			if ( (v == 0) || (v == ~0ULL) || (v == 1) || (v == codeAddress(3)) ) {
				for (unsigned i = 0; i != 8; ++i)
					if ( (row.stripMask >> i) & 1 )
						CHECK(gSeen[i] == v, "%s arg %u: 0x%llx must survive, got 0x%llx", row.symbol, i, (unsigned long long)v, (unsigned long long)gSeen[i]);
			}
			if ( v == values[0] )
				for (unsigned i = 0; i != 8; ++i)
					if ( (row.stripMask >> i) & 1 )
						CHECK(gSeen[i] == codeAddress(2), "%s arg %u: a signed pointer did not come out as the plain one", row.symbol, i);
		}
	}
	CHECK(rowsRun >= 8, "only %d strip rows ran", rowsRun);
}

static void checkSignal()
{
	Fn8 t = thunkFor("_signal");
	const uint64_t handler = oracleSign(codeAddress(5), 0);
	const uint64_t plainReturns[] = { codeAddress(6), 0, 1, ~0ULL };
	for (uint64_t ret : plainReturns) {
		gFakeResult = ret;
		const uint64_t result = t(30, handler, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[0] == 30, "signal: the signal number changed");
		CHECK(gSeen[1] == codeAddress(5), "signal: the handler arrived as 0x%llx", (unsigned long long)gSeen[1]);
		if ( (ret == 0) || (ret == 1) || (ret == ~0ULL) )
			CHECK(result == ret, "signal: special value 0x%llx came back as 0x%llx", (unsigned long long)ret, (unsigned long long)result);
		else {
			CHECK(result != ret, "signal: the returned handler was not signed");
			CHECK(oracleAuth(result, 0) == ret, "signal: the returned handler does not authenticate with key IA, discriminator 0");
		}
	}
	// SIG_IGN as the argument survives
	t(30, 1, 0, 0, 0, 0, 0, 0);
	CHECK(gSeen[1] == 1, "signal: SIG_IGN changed");
}

static Block gHeapResult;
static void checkBlockCopy()
{
	Fn8 t = thunkFor("__Block_copy");
	// a copy keeps the signature made for the old address
	const uint64_t target = codeAddress(7);
	void* stale = (void*)oracleSign(target, (uint64_t)&gHeapResult.invoke + 0x100);
	gHeapResult = { nullptr, kHeap, 0, stale, nullptr };
	gFakeResult = (uint64_t)&gHeapResult;
	const uint64_t result = t(0x77, 0, 0, 0, 0, 0, 0, 0);
	CHECK(result == (uint64_t)&gHeapResult, "Block_copy: the block pointer changed");
	CHECK(oracleAuth((uint64_t)gHeapResult.invoke, (uint64_t)&gHeapResult.invoke) == target, "Block_copy: invoke is not signed for its own address (IA, address-diversified, discriminator 0)");
	CHECK(gHeapResult.flags == kHeap, "Block_copy: flags changed");

	// the same pointer twice: re-signing is idempotent
	t(0x77, 0, 0, 0, 0, 0, 0, 0);
	CHECK(oracleAuth((uint64_t)gHeapResult.invoke, (uint64_t)&gHeapResult.invoke) == target, "Block_copy: a second call broke the signature");

	// a plain (unsigned) invoke from a plain library gets signed
	gHeapResult.invoke = (void*)target;
	t(0x77, 0, 0, 0, 0, 0, 0, 0);
	CHECK(oracleAuth((uint64_t)gHeapResult.invoke, (uint64_t)&gHeapResult.invoke) == target, "Block_copy: an unsigned invoke was not signed");

	// a global block comes back as it is (its literal is read-only), and NULL stays NULL
	CHECK(gGlobalBlock->invoke != (void*)oracleStrip((uint64_t)gGlobalBlock->invoke), "the global block of this test is not signed");
	const void* signedInvoke = gGlobalBlock->invoke;
	gFakeResult = (uint64_t)gGlobalBlock;
	CHECK(t(0x77, 0, 0, 0, 0, 0, 0, 0) == (uint64_t)gGlobalBlock && gGlobalBlock->invoke == signedInvoke, "Block_copy: a global block was touched");
	gFakeResult = 0;
	CHECK(t(0x77, 0, 0, 0, 0, 0, 0, 0) == 0, "Block_copy: NULL");
}

static void checkDispatch()
{
	for (const char* name : { "_dispatch_async", "_dispatch_once" }) {
		Fn8 t = thunkFor(name);
		const uint64_t target = codeAddress(8);
		gFakeResult = 0;
		gHook = snapshotBlock;

		// a stack block: stripped during the call, its own signature back afterwards
		Block stack = { nullptr, 0, 0, (void*)oracleSign(target, 0), nullptr };
		void* original = stack.invoke;
		t(0x1010, (uint64_t)&stack, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[0] == 0x1010 && gSeen[1] == (uint64_t)&stack, "%s: the arguments changed", name);
		CHECK(gBlockInvokeSeen == target, "%s: the callee saw invoke 0x%llx", name, (unsigned long long)gBlockInvokeSeen);
		CHECK(stack.invoke == original, "%s: the caller's stack block did not get its signature back", name);

		// a heap block: stripped for good (the callee keeps it)
		Block heap = { nullptr, kHeap, 0, (void*)oracleSign(target, 0), nullptr };
		t(0x1010, (uint64_t)&heap, 0, 0, 0, 0, 0, 0);
		CHECK(gBlockInvokeSeen == target && heap.invoke == (void*)target, "%s: heap block", name);

		// a global block lives in read-only memory: the callee gets a stripped mirror, the literal is untouched
		t(0x1010, (uint64_t)gGlobalBlock, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] != (uint64_t)gGlobalBlock, "%s: a global block was passed on in place", name);
		const Block* mirror = (const Block*)gSeen[1];
		CHECK(mirror->flags == kGlobal && (uint64_t)mirror->invoke == oracleStrip((uint64_t)gGlobalBlock->invoke), "%s: mirror", name);
		const uint64_t firstMirror = gSeen[1];
		t(0x1010, (uint64_t)gGlobalBlock, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] == firstMirror, "%s: a second call made a second mirror", name);

		// NULL block
		t(0x1010, 0, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] == 0, "%s: NULL block", name);
		gHook = nullptr;
	}
}

static void checkSigaction()
{
	Fn8 t = thunkFor("_sigaction");
	const uint64_t handler = oracleSign(codeAddress(9), 0);
	struct Act { uint64_t handler; uint32_t mask; int32_t flags; };
	Act act = { handler, 0xa5a5, 0x42 };
	uint64_t oact[2] = { 7, 7 };
	static Act seen;
	gHook = [](const uint64_t* a) { if (a[1]) memcpy(&seen, (const void*)a[1], sizeof(seen)); };
	gFakeResult = 0;
	t(30, (uint64_t)&act, (uint64_t)oact, 0, 0, 0, 0, 0);
	CHECK(gSeen[0] == 30 && gSeen[2] == (uint64_t)oact, "sigaction: the other arguments changed");
	CHECK(gSeen[1] != (uint64_t)&act, "sigaction: the caller's struct was passed on in place");
	CHECK(seen.handler == codeAddress(9) && seen.mask == 0xa5a5 && seen.flags == 0x42, "sigaction: handler 0x%llx mask 0x%x flags 0x%x", (unsigned long long)seen.handler, seen.mask, seen.flags);
	CHECK(act.handler == handler, "sigaction: the caller's struct changed");
	// the caller's struct may be read-only, so the strip cannot be done in place
	static const Act readOnlyAct = { 0x00aa000100003000ULL, 1, 2 };
	t(30, (uint64_t)&readOnlyAct, 0, 0, 0, 0, 0, 0);
	CHECK(seen.handler == oracleStrip(readOnlyAct.handler), "sigaction: a read-only struct");
	t(30, 0, 0, 0, 0, 0, 0, 0);
	CHECK(gSeen[1] == 0 && gSeen[2] == 0, "sigaction: NULL act and oact");
	gHook = nullptr;
}

static void checkBind()
{
	gWarnings.clear();
	CHECK(adaptedTarget("_not_a_row", 0x1234, false) == 0x1234, "an unknown symbol was adapted");
	CHECK(adaptedTarget("_atexit", 0x1234, true) == 0x1234, "an arm64e target was adapted");
	CHECK(gWarnings.empty(), "unexpected warnings: %s", gWarnings.c_str());

	const uint64_t a = adaptedTarget("_atexit", 0x4000, false), b = adaptedTarget("_atexit", 0x4000, false), c = adaptedTarget("_atexit", 0x5000, false);
	CHECK(a != 0x4000 && a == b, "the same row and target must share one thunk");
	CHECK(c != a, "another target needs its own thunk");

	CHECK(adaptedTarget("_atexit_b", 0x1234, false) == 0x1234, "an unsupported row changed the binding");
	CHECK(gWarnings.find("_atexit_b") != std::string::npos && gWarnings.find("no adapter") != std::string::npos, "an unsupported row did not warn loudly: '%s'", gWarnings.c_str());

	setAdaptersEnabled(false);
	CHECK(adaptedTarget("_atexit", 0x7000, false) == 0x7000, "the kill switch did not turn the adapters off");
	setAdaptersEnabled(true);
	CHECK(adaptedTarget("_atexit", 0x7000, false) != 0x7000, "the adapters did not come back");
}

int main(int argc, char** argv)
{
	if ( (argc > 1) && (strcmp(argv[1], "rows") == 0) ) {
		size_t n;
		const AdapterRow* rows = adapterRows(&n);
		for (size_t i = 0; i != n; ++i)
			printf("ROW %s %u %u %u %d %u %d\n", rows[i].symbol, rows[i].stripMask, rows[i].blockArg, rows[i].structArg, (int)rows[i].ret, rows[i].argCount, (int)rows[i].status);
		return 0;
	}
	if ( (argc > 2) && (strcmp(argv[1], "strip-thunk") == 0) ) {
		uint32_t w[16];
		const size_t n = emitStripThunk(w, (uint8_t)strtoul(argv[2], nullptr, 0), 0x1122334455667788ULL);
		for (size_t i = 0; i != n; ++i)
			printf("%08x\n", w[i]);
		return 0;
	}
	if ( (argc > 2) && (strcmp(argv[1], "call-thunk") == 0) ) {
		const AdapterRow* row = findAdapterRow(argv[2]);
		if ( row == nullptr )
			return 2;
		uint32_t w[20];
		const size_t n = emitCallThunk(w, row, 0x1122334455667788ULL);
		printf("ROWADDR %016llx HELPER %016llx\n", (unsigned long long)(uint64_t)row, (unsigned long long)callThunkHelperAddress());
		for (size_t i = 0; i != n; ++i)
			printf("%08x\n", w[i]);
		return 0;
	}
	checkPacWorks();
	makeGlobalBlock();
	checkTable();
	checkStripRows();
	checkSignal();
	checkBlockCopy();
	checkDispatch();
	checkSigaction();
	checkBind();
	printf("%s %d checks, %d failures\n", gFailures ? "FAIL" : "PASS", gChecks, gFailures);
	return gFailures ? 1 : 0;
}
