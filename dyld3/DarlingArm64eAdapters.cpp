// DARLING arm64e compat: see DarlingArm64eAdapters.h.
#include "DarlingArm64eAdapters.h"

#include <string.h>
#include <sys/mman.h>

namespace dyld {
	extern void warn(const char* format, ...) __attribute__((format(printf, 1, 2)));
}

namespace dyld3 {
namespace darling {

#if defined(__aarch64__) || defined(__arm64__)

// The evidence strings name the checks of tests/arm64e-link/abi (L2 ABI probe), which stripped exactly these pointers
// and passed in 6 of 6 boots.
static const AdapterRow kRows[] = {
	{ "___cxa_atexit",		0x1, 0, 0, ReturnFix::None, 3, AdapterStatus::Probed,    "L2 check 02" },
	{ "_atexit",			0x1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed,    "L2 check 01" },
	{ "_pthread_key_create",0x2, 0, 0, ReturnFix::None, 2, AdapterStatus::Probed,    "L2 check 03" },
	{ "_pthread_create",	0x4, 0, 0, ReturnFix::None, 4, AdapterStatus::Probed,    "L2 check 04" },
	{ "_pthread_once",		0x2, 0, 0, ReturnFix::None, 2, AdapterStatus::Probed,    "L2 check 05" },
	{ "_qsort",				0x8, 0, 0, ReturnFix::None, 4, AdapterStatus::Probed,    "L2 check 06" },
	{ "__dyld_register_func_for_add_image", 0x1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "L2 check 10" },
	{ "__tlv_atexit",		0x1, 0, 0, ReturnFix::None, 2, AdapterStatus::ShapeOnly, "the shape of checks 01 and 03, not run" },
	{ "__dyld_register_func_for_remove_image", 0x1, 0, 0, ReturnFix::None, 1, AdapterStatus::ShapeOnly, "the shape of check 10, not run" },
};

static bool sEnabled = true;

void setAdaptersEnabled(bool enabled)
{
	sEnabled = enabled;
}

const AdapterRow* adapterRows(size_t* count)
{
	*count = sizeof(kRows) / sizeof(kRows[0]);
	return kRows;
}

const AdapterRow* findAdapterRow(const char* symbol)
{
	for (const AdapterRow& row : kRows) {
		if ( strcmp(row.symbol, symbol) == 0 )
			return &row;
	}
	return nullptr;
}

const char* validateAdapterRows(const AdapterRow* rows, size_t count)
{
	for (size_t i = 0; i != count; ++i) {
		const AdapterRow& r = rows[i];
		if ( (r.symbol == nullptr) || (r.symbol[0] != '_') )
			return "a symbol is missing the Mach-O underscore";
		for (size_t j = 0; j != i; ++j) {
			if ( strcmp(rows[j].symbol, r.symbol) == 0 )
				return "a symbol has two rows";
		}
		if ( (r.evidence == nullptr) || (r.evidence[0] == '\0') )
			return "a row has no evidence";
		const bool acts = (r.stripMask != 0) || (r.blockArg != 0) || (r.structArg != 0) || (r.ret != ReturnFix::None);
		if ( r.status == AdapterStatus::Unsupported ) {
			if ( acts )
				return "an unsupported row has an action";
			continue;
		}
		if ( !acts )
			return "a row does nothing";
		if ( (r.argCount == 0) || (r.argCount > 8) )
			return "a row takes no register argument or more than eight";
		if ( (r.stripMask >> r.argCount) != 0 )
			return "a strip mask names an argument the row does not have";
		if ( (r.blockArg > r.argCount) || (r.structArg > r.argCount) )
			return "a block or struct argument is out of range";
		if ( (r.blockArg != 0) && (r.structArg != 0) )
			return "a row has both a block and a struct argument";
		if ( (r.blockArg != 0) && ((r.stripMask >> (r.blockArg - 1)) & 1) )
			return "the block argument is also in the strip mask";
		if ( (r.structArg != 0) && ((r.stripMask >> (r.structArg - 1)) & 1) )
			return "the struct argument is also in the strip mask";
	}
	return nullptr;
}

// ------------------------------------------------------------------------------------------ thunks

static const uint32_t kNop = 0xD503201F;

static void putLiteral(uint32_t* words, uint64_t value)
{
	words[0] = (uint32_t)value;
	words[1] = (uint32_t)(value >> 32);
}

// xpaci xN for each masked argument, then a tail branch: no frame, no stack, the link register stays the caller's.
size_t emitStripThunk(uint32_t* words, uint8_t stripMask, uint64_t real)
{
	size_t n = 0;
	// the literal is 8 bytes after the ldr and must be 8 aligned
	if ( (__builtin_popcount(stripMask) & 1) != 0 )
		words[n++] = kNop;
	for (unsigned i = 0; i != 8; ++i) {
		if ( (stripMask >> i) & 1 )
			words[n++] = 0xDAC143E0 | i;
	}
	words[n++] = 0x58000050;	// ldr x16, #8
	words[n++] = 0xD61F0200;	// br x16
	putLiteral(&words[n], real);
	return n + 2;
}

// One page of executable thunks, filled once and never rewritten. Linux ignores W^X, so the page is mapped writable
// and executable once and no thread ever finds a thunk's page without execute permission.
static const size_t kThunkPageSize = 16384;
static uint8_t* sThunkPage;
static size_t sThunkUsed;

struct ThunkEntry { const AdapterRow* row; uint64_t real; uint64_t thunk; };
static ThunkEntry sThunks[128];
static size_t sThunkCount;

static void flushInstructionCache(void* start, size_t length)
{
	uint64_t ctr;
	__asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
	const uintptr_t dline = 4UL << ((ctr >> 16) & 0xf);
	const uintptr_t iline = 4UL << (ctr & 0xf);
	const uintptr_t first = (uintptr_t)start, last = first + length;
	for (uintptr_t a = first & ~(dline - 1); a < last; a += dline)
		__asm__ volatile("dc cvau, %0" : : "r"(a) : "memory");
	__asm__ volatile("dsb ish" : : : "memory");
	for (uintptr_t a = first & ~(iline - 1); a < last; a += iline)
		__asm__ volatile("ic ivau, %0" : : "r"(a) : "memory");
	__asm__ volatile("dsb ish\n\tisb" : : : "memory");
}

// 0 when the page cannot be had
static uint64_t emitThunk(const AdapterRow* row, uint64_t real)
{
	for (size_t i = 0; i != sThunkCount; ++i) {
		if ( (sThunks[i].row == row) && (sThunks[i].real == real) )
			return sThunks[i].thunk;
	}
	if ( sThunkCount == sizeof(sThunks) / sizeof(sThunks[0]) )
		return 0;
	if ( sThunkPage == nullptr ) {
		void* page = mmap(nullptr, kThunkPageSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
		if ( page == MAP_FAILED )
			return 0;
		sThunkPage = (uint8_t*)page;
	}
	uint32_t words[20];
	const size_t count = emitStripThunk(words, row->stripMask, real);
	const size_t bytes = (count * sizeof(uint32_t) + 15) & ~(size_t)15;
	if ( sThunkUsed + bytes > kThunkPageSize )
		return 0;
	uint8_t* at = sThunkPage + sThunkUsed;
	memcpy(at, words, count * sizeof(uint32_t));
	flushInstructionCache(at, count * sizeof(uint32_t));
	sThunkUsed += bytes;
	sThunks[sThunkCount++] = { row, real, (uint64_t)at };
	return (uint64_t)at;
}

// ------------------------------------------------------------------------------------------ bind time

uint64_t adaptedTarget(const char* symbol, uint64_t target, bool targetIsArm64e)
{
	if ( !sEnabled || targetIsArm64e )
		return target;
	const AdapterRow* row = findAdapterRow(symbol);
	if ( row == nullptr )
		return target;
	if ( row->status == AdapterStatus::Unsupported ) {
		dyld::warn("arm64e adapters: %s is imported by an arm64e image and has no adapter (%s); calls with a signed pointer fault\n",
				   symbol, row->evidence);
		return target;
	}
	const uint64_t thunk = emitThunk(row, target);
	if ( thunk == 0 ) {
		dyld::warn("arm64e adapters: no room for a thunk for %s; it is bound unadapted and calls with a signed pointer fault\n", symbol);
		return target;
	}
	return thunk;
}

#else // not arm64: arm64e importers do not exist, so nothing is ever adapted

static const AdapterRow kRows[] = { { "_unused", 0, 0, 0, ReturnFix::None, 0, AdapterStatus::Unsupported, "not arm64" } };
void setAdaptersEnabled(bool) { }
const AdapterRow* adapterRows(size_t* count) { *count = 0; return kRows; }
const AdapterRow* findAdapterRow(const char*) { return nullptr; }
const char* validateAdapterRows(const AdapterRow*, size_t) { return nullptr; }
uint64_t adaptedTarget(const char*, uint64_t target, bool) { return target; }
size_t emitStripThunk(uint32_t*, uint8_t, uint64_t) { return 0; }

#endif

} // namespace darling
} // namespace dyld3
