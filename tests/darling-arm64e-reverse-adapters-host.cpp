// Native driver of tests/darling-arm64e-reverse-adapters.rb: the opposite-direction thunks (a PLAIN importer binding an
// export of an arm64e image) of dyld3/DarlingArm64eAdapters.cpp on this arm64 host with real pointer authentication.
// The expectations use PAC instructions directly (pacia, autia, xpaci), not the module's helpers. `rows` prints the table.
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

__attribute__((target("arch=armv8.3-a"))) static uint64_t oracleSign(uint64_t p, uint64_t modifier) { asm("pacia %0, %1" : "+r"(p) : "r"(modifier)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t oracleAuth(uint64_t p, uint64_t modifier) { asm("autia %0, %1" : "+r"(p) : "r"(modifier)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t oracleStrip(uint64_t p) { asm("xpaci %0" : "+r"(p)); return p; }

// the fake arm64e callee: records its arguments and returns what the test put in gResult
static uint64_t gSeen[8];
static int gCalls;
static uint64_t gResult;
static uint64_t fakeCallee(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
	const uint64_t a[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
	memcpy(gSeen, a, sizeof(a));
	++gCalls;
	return gResult;
}
typedef uint64_t (*Fn8)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

// code addresses are those in [kCodeLow, kCodeHigh); everything else is data to the predicate
static const uint64_t kCodeLow = 0x0000000100003000ULL, kCodeHigh = 0x0000000100009000ULL;
static bool gPredicateCalls;
static bool isCode(uint64_t a) { gPredicateCalls = true; return (a >= kCodeLow) && (a < kCodeHigh); }
static uint64_t codeAddress(int n) { return kCodeLow + 0x40 * n; }
// an address whose signature differs from the address, and from its signature under another modifier
static uint64_t goodCode(int n)
{
	uint64_t p = codeAddress(n);
	while ( (oracleSign(p, 0) == p) || (oracleSign(p, 1) == oracleSign(p, 0)) )
		p += 0x40;
	return p;
}

static Fn8 thunkFor(const char* symbol)
{
	const uint64_t t = reverseAdaptedTarget(symbol, (uint64_t)&fakeCallee, true, &isCode);
	CHECK(t != (uint64_t)&fakeCallee, "%s was not adapted", symbol);
	return (Fn8)t;
}

static const uint64_t kS[8] = { 0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444,
								0x5555555555555555, 0x6666666666666666, 0x7777777777777777, 0x0888888888888888 };

static uint64_t callWith(Fn8 f, const uint64_t* args) { return f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]); }

static void checkTable()
{
	size_t n = 0;
	const ReverseRow* rows = reverseRows(&n);
	const char* error = validateReverseRows(rows, n);
	CHECK(error == nullptr, "built-in table: %s", error ? error : "");
	CHECK(n >= 20, "rows: %zu", n);
	ReverseRow bad[2] = { { "_a", 1, false, 1, AdapterStatus::Probed, "e" }, { "_a", 1, false, 1, AdapterStatus::Probed, "e" } };
	CHECK(validateReverseRows(bad, 2) != nullptr, "a duplicate symbol was accepted");
	ReverseRow noop[1] = { { "_a", 0, false, 1, AdapterStatus::Probed, "e" } };
	CHECK(validateReverseRows(noop, 1) != nullptr, "a row that does nothing was accepted");
	ReverseRow range[1] = { { "_a", 0x4, false, 2, AdapterStatus::Probed, "e" } };
	CHECK(validateReverseRows(range, 1) != nullptr, "a mask naming a missing argument was accepted");
	ReverseRow noev[1] = { { "_a", 1, false, 1, AdapterStatus::Probed, "" } };
	CHECK(validateReverseRows(noev, 1) != nullptr, "a row without evidence was accepted");
	ReverseRow unsupportedActs[1] = { { "_a", 1, false, 1, AdapterStatus::Unsupported, "e" } };
	CHECK(validateReverseRows(unsupportedActs, 1) != nullptr, "an unsupported row with an action was accepted");
}

static void checkSetHandler()
{
	// set_terminate: argument 0 signed IA/0, the old handler comes back stripped
	Fn8 f = thunkFor("__ZSt13set_terminatePFvvE");
	const uint64_t h = goodCode(1), old = goodCode(2);
	uint64_t args[8]; memcpy(args, kS, sizeof(args));
	args[0] = h;
	gResult = oracleSign(old, 0);
	gCalls = 0;
	const uint64_t r = callWith(f, args);
	CHECK(gCalls == 1, "callee called %d times", gCalls);
	CHECK(gSeen[0] == oracleSign(h, 0), "the callee did not get the IA/0 signature of the handler: %llx", (unsigned long long)gSeen[0]);
	CHECK(oracleAuth(gSeen[0], 0) == h, "the signed handler does not authenticate under IA/0");
	CHECK(oracleAuth(gSeen[0], 1) != h, "control: it must not authenticate under another modifier");
	for (int i = 1; i < 8; ++i)
		CHECK(gSeen[i] == kS[i], "argument %d changed", i);
	CHECK(r == old, "the old handler came back as %llx, not stripped to %llx", (unsigned long long)r, (unsigned long long)old);
	CHECK(r == oracleStrip(r), "the result still carries a signature");

	// NULL: never signed
	args[0] = 0; gResult = 0; callWith(f, args);
	CHECK(gSeen[0] == 0, "NULL was changed to %llx", (unsigned long long)gSeen[0]);

	// a data address (not in a code window) passes unchanged: not a signing oracle for data
	args[0] = 0x0000000200001000ULL; callWith(f, args);
	CHECK(gSeen[0] == 0x0000000200001000ULL, "a data address was signed");
	args[0] = 0xdeadbeef; callWith(f, args);
	CHECK(gSeen[0] == 0xdeadbeef, "garbage was signed");

	// a value that already carries a signature (a round trip through plain code) is not in a code window: unchanged
	const uint64_t signedAlready = oracleSign(h, 0);
	args[0] = signedAlready; callWith(f, args);
	CHECK(gSeen[0] == signedAlready, "an already signed pointer was changed");
	// control for the window: the same address stripped is signed
	args[0] = h; callWith(f, args);
	CHECK(gSeen[0] == oracleSign(h, 0), "control: the stripped address was not signed");
}

static void checkGetters()
{
	for (const char* sym : { "__ZSt13get_terminatev", "__ZSt14get_unexpectedv", "__ZSt15get_new_handlerv" }) {
		Fn8 f = thunkFor(sym);
		const uint64_t h = goodCode(3);
		gResult = oracleSign(h, 0); gCalls = 0;
		const uint64_t r = callWith(f, kS);
		CHECK(r == h, "%s result %llx not stripped to %llx", sym, (unsigned long long)r, (unsigned long long)h);
		for (int i = 0; i < 8; ++i)
			CHECK(gSeen[i] == kS[i], "%s argument %d changed", sym, i);
		gResult = 0; callWith(f, kS);
		CHECK(callWith(f, kS) == 0, "%s: a NULL handler came back as non-zero", sym);
	}
}

static void checkArgPositions()
{
	// the dest of __cxa_throw is argument 2; the others pass; the result is not touched (a typeinfo pointer is data)
	Fn8 f = thunkFor("___cxa_throw");
	uint64_t args[8]; memcpy(args, kS, sizeof(args));
	args[0] = 0x0000000200002000ULL; args[1] = 0x0000000200003000ULL; args[2] = goodCode(4);
	gResult = 0x1234;
	const uint64_t r = callWith(f, args);
	CHECK(gSeen[2] == oracleSign(args[2], 0), "dest was not signed");
	CHECK(gSeen[0] == args[0] && gSeen[1] == args[1], "the object or the typeinfo changed");
	CHECK(r == 0x1234, "a result that is not a handler changed: %llx", (unsigned long long)r);
	// a row with two masked arguments: strstreambuf(this, alloc, free)
	f = thunkFor("__ZNSt3__112strstreambufC1EPFPvmEPFvS1_E");
	memcpy(args, kS, sizeof(args));
	args[0] = 0x0000000200002000ULL; args[1] = goodCode(5); args[2] = goodCode(6);
	callWith(f, args);
	CHECK(gSeen[0] == args[0], "this changed");
	CHECK(gSeen[1] == oracleSign(args[1], 0) && gSeen[2] == oracleSign(args[2], 0), "an alloc or free pointer was not signed");
	// a manipulator is argument 1
	f = thunkFor("__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEPFRS3_S4_E");
	memcpy(args, kS, sizeof(args));
	args[0] = 0x0000000200002000ULL; args[1] = goodCode(7);
	callWith(f, args);
	CHECK(gSeen[0] == args[0] && gSeen[1] == oracleSign(args[1], 0), "the manipulator was not signed");
}

static void checkPolicy()
{
	CHECK(reverseAdaptedTarget("__ZSt13set_terminatePFvvE", 0x1234, false, &isCode) == 0x1234, "an exporter that is plain was adapted");
	CHECK(reverseAdaptedTarget("_not_a_row", 0x1234, true, &isCode) == 0x1234, "an unknown symbol was adapted");
	// no predicate: nothing is signed
	const uint64_t t = reverseAdaptedTarget("__ZSt15set_new_handlerPFvvE", (uint64_t)&fakeCallee, true, nullptr);
	CHECK(t != (uint64_t)&fakeCallee, "no thunk without a predicate");
	uint64_t args[8]; memcpy(args, kS, sizeof(args)); args[0] = goodCode(8);
	callWith((Fn8)t, args);
	CHECK(gSeen[0] == args[0], "a pointer was signed with no predicate to vouch for it");
	// an unsupported row binds the target and warns
	gWarnings.clear();
	size_t n = 0; const ReverseRow* rows = reverseRows(&n);
	const char* unsupported = nullptr;
	for (size_t i = 0; i != n; ++i)
		if ( rows[i].status == AdapterStatus::Unsupported ) unsupported = rows[i].symbol;
	CHECK(unsupported != nullptr, "no unsupported row in the table");
	if ( unsupported ) {
		CHECK(reverseAdaptedTarget(unsupported, 0x1234, true, &isCode) == 0x1234, "an unsupported row was adapted");
		CHECK(gWarnings.find(unsupported) != std::string::npos, "an unsupported row did not warn");
	}
	setAdapterMode(AdapterMode::Off);
	CHECK(reverseAdaptedTarget("__ZSt13set_terminatePFvvE", 0x1234, true, &isCode) == 0x1234, "mode off still adapted");
	setAdapterMode(AdapterMode::On);
	// a thunk is made once per symbol and target
	CHECK(reverseAdaptedTarget("__ZSt13set_terminatePFvvE", (uint64_t)&fakeCallee, true, &isCode) == reverseAdaptedTarget("__ZSt13set_terminatePFvvE", (uint64_t)&fakeCallee, true, &isCode), "two thunks for one symbol and target");
}

static void checkThunkPage()
{
	const uint64_t t = reverseAdaptedTarget("__ZSt13set_terminatePFvvE", (uint64_t)&fakeCallee, true, &isCode);
	FILE* maps = fopen("/proc/self/maps", "r");
	char line[512]; bool found = false, rx = false;
	while ( maps && fgets(line, sizeof(line), maps) ) {
		unsigned long lo, hi; char perms[8];
		if ( sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) == 3 && t >= lo && t < hi ) { found = true; rx = strcmp(perms, "r-xp") == 0; }
	}
	if ( maps ) fclose(maps);
	CHECK(found && rx, "the thunk page is not r-x");
}

int main(int argc, char** argv)
{
	if ( argc >= 2 && strcmp(argv[1], "rows") == 0 ) {
		size_t n = 0; const ReverseRow* rows = reverseRows(&n);
		for (size_t i = 0; i != n; ++i)
			printf("%s %x %d %d %d\n", rows[i].symbol, rows[i].signMask, rows[i].stripReturn, rows[i].argCount, (int)rows[i].status);
		return 0;
	}
	checkTable();
	checkSetHandler();
	checkGetters();
	checkArgPositions();
	checkPolicy();
	checkThunkPage();
	printf("%d checks, %d failures\n", gChecks, gFailures);
	return gFailures == 0 ? 0 : 1;
}
