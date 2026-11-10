// DARLING arm64e compat: see DarlingArm64eAdapters.h.
#include "DarlingArm64eAdapters.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "MachOLoaded.h"

namespace dyld {
	extern void warn(const char* format, ...) __attribute__((format(printf, 1, 2)));
}

namespace dyld3 {
namespace darling {

#if defined(__aarch64__) || defined(__arm64__)

using AdapterSign = dyld3::MachOLoaded::ChainedFixupPointerOnDisk::Arm64e;

// The evidence strings name the checks of tests/arm64e-link/abi (L2 ABI probe), which stripped (01-10, 18) or
// re-signed (17, 19) exactly these pointers and passed in 6 of 6 boots.
static const AdapterRow kRows[] = {
	{ "___cxa_atexit",		0x1, 0, 0, ReturnFix::None, 3, AdapterStatus::Probed,    "L2 check 02" },
	{ "_atexit",			0x1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed,    "L2 check 01" },
	{ "_pthread_key_create",0x2, 0, 0, ReturnFix::None, 2, AdapterStatus::Probed,    "L2 check 03" },
	{ "_pthread_create",	0x4, 0, 0, ReturnFix::None, 4, AdapterStatus::Probed,    "L2 check 04" },
	{ "_pthread_once",		0x2, 0, 0, ReturnFix::None, 2, AdapterStatus::Probed,    "L2 check 05" },
	{ "_qsort",				0x8, 0, 0, ReturnFix::None, 4, AdapterStatus::Probed,    "L2 check 06" },
	{ "__dyld_register_func_for_add_image", 0x1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "L2 check 10" },
	{ "_dispatch_async",	0x0, 2, 0, ReturnFix::None, 2, AdapterStatus::Probed,    "L2 checks 07, 08 (stack and global block; a heap block is stripped in place and stays stripped)" },
	{ "_dispatch_once",		0x0, 2, 0, ReturnFix::None, 2, AdapterStatus::Probed,    "L2 check 09" },
	{ "_sigaction",			0x0, 0, 2, ReturnFix::None, 3, AdapterStatus::Probed,    "L2 check 18 (the old-action out parameter is not re-signed: not shown)" },
	{ "_signal",			0x2, 0, 0, ReturnFix::SignFunctionIA0, 2, AdapterStatus::Probed, "L2 check 19" },
	{ "__Block_copy",		0x0, 0, 0, ReturnFix::ResignBlockInvoke, 1, AdapterStatus::Probed, "L2 check 17" },
	{ "__tlv_atexit",		0x1, 0, 0, ReturnFix::None, 2, AdapterStatus::ShapeOnly, "the shape of checks 01 and 03, not run" },
	{ "__dyld_register_func_for_remove_image", 0x1, 0, 0, ReturnFix::None, 1, AdapterStatus::ShapeOnly, "the shape of check 10, not run" },
	{ "_dispatch_block_create",	0, 0, 0, ReturnFix::None, 0, AdapterStatus::Unsupported, "a block returned to arm64e code: the key and diversifier of what plain code builds are not shown (L2 README, Not verified)" },
	{ "_atexit_b",			0, 0, 0, ReturnFix::None, 0, AdapterStatus::Unsupported, "block arguments other than dispatch_async and dispatch_once are not shown (L2 README, Not verified)" },
	{ "_qsort_b",			0, 0, 0, ReturnFix::None, 0, AdapterStatus::Unsupported, "block arguments other than dispatch_async and dispatch_once are not shown (L2 README, Not verified)" },
};

// A Block_literal_1. flags: 1<<24 BLOCK_NEEDS_FREE (heap), 1<<28 BLOCK_IS_GLOBAL.
struct BlockLiteral {
	void*		isa;
	int32_t		flags;
	int32_t		reserved;
	void*		invoke;
	void*		descriptor;
};
static_assert(sizeof(BlockLiteral) == 32, "block literal layout");
static const int32_t kBlockNeedsFree = 1 << 24;
static const int32_t kBlockIsGlobal  = 1 << 28;

// XPACI: the identity on an unsigned canonical pointer, so one strip serves signed and plain callers alike.
static inline uint64_t stripCode(uint64_t pointer)
{
	uint64_t stripped;
	// the .inst form because the plain arm64 assembler of this build refuses xpaci; this is xpaci x17
	__asm__("mov x17, %1\n\t.inst 0xDAC143F1\n\tmov %0, x17" : "=r"(stripped) : "r"(pointer) : "x17");
	return stripped;
}

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

static uint64_t callRow(uint64_t* regs, const AdapterRow* row, uint64_t real);

uint64_t callThunkHelperAddress()
{
	return (uint64_t)&callRow;
}

// Saves x0-x7 below a frame record, then callRow(regs, row, real) does the work and returns the result in x0.
size_t emitCallThunk(uint32_t* words, const AdapterRow* row, uint64_t real)
{
	static const uint32_t kTemplate[14] = {
		0xA9BB7BFD,		// stp x29, x30, [sp, #-80]!
		0x910003FD,		// mov x29, sp
		0xA90107E0,		// stp x0, x1, [sp, #16]
		0xA9020FE2,		// stp x2, x3, [sp, #32]
		0xA90317E4,		// stp x4, x5, [sp, #48]
		0xA9041FE6,		// stp x6, x7, [sp, #64]
		0x910043E0,		// add x0, sp, #16
		0x580000E1,		// ldr x1, row
		0x58000102,		// ldr x2, real
		0x58000130,		// ldr x16, helper
		0xD63F0200,		// blr x16
		0xA8C57BFD,		// ldp x29, x30, [sp], #80
		0xD65F03C0,		// ret
		0xD503201F,		// nop (the literals are 8 aligned)
	};
	memcpy(words, kTemplate, sizeof(kTemplate));
	putLiteral(&words[14], (uint64_t)row);
	putLiteral(&words[16], real);
	putLiteral(&words[18], callThunkHelperAddress());
	return 20;
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
	const bool simple = (row->blockArg == 0) && (row->structArg == 0) && (row->ret == ReturnFix::None);
	const size_t count = simple ? emitStripThunk(words, row->stripMask, real) : emitCallThunk(words, row, real);
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

// ------------------------------------------------------------------------------------------ the call thunk's work

// The mirror of a global block: its literal can be read-only, so a stripped copy is what plain code gets. Global
// blocks are never freed, so the mirrors are kept, one per block address, and refreshed on every use.
struct Mirror { const BlockLiteral* original; BlockLiteral* copy; };
static Mirror sMirrors[256];
static size_t sMirrorCount;
static volatile int sMirrorLock;

static BlockLiteral* mirrorOfGlobalBlock(const BlockLiteral* block)
{
	while ( __sync_lock_test_and_set(&sMirrorLock, 1) ) { }
	BlockLiteral* copy = nullptr;
	for (size_t i = 0; i != sMirrorCount; ++i) {
		if ( sMirrors[i].original == block ) {
			copy = sMirrors[i].copy;
			break;
		}
	}
	if ( copy == nullptr ) {
		if ( sMirrorCount == sizeof(sMirrors) / sizeof(sMirrors[0]) ) {
			dyld::warn("arm64e adapters: more than %lu distinct global blocks passed to plain code\n", (unsigned long)(sizeof(sMirrors) / sizeof(sMirrors[0])));
			__builtin_trap();
		}
		copy = (BlockLiteral*)malloc(sizeof(BlockLiteral));
		sMirrors[sMirrorCount++] = { block, copy };
	}
	*copy = *block;
	copy->invoke = (void*)stripCode((uint64_t)block->invoke);
	__sync_lock_release(&sMirrorLock);
	return copy;
}

static uint64_t signFunctionIA0(uint64_t pointer)
{
	// SIG_DFL, SIG_IGN and SIG_ERR are not code
	if ( (pointer == 0) || (pointer == 1) || (pointer == ~0ULL) )
		return pointer;
	return AdapterSign::signPointer(pointer, nullptr, false, 0, 0);
}

typedef uint64_t (*Call8)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static uint64_t callRow(uint64_t* regs, const AdapterRow* row, uint64_t real)
{
	uint64_t a[8];
	memcpy(a, regs, sizeof(a));
	for (unsigned i = 0; i != 8; ++i) {
		if ( (row->stripMask >> i) & 1 )
			a[i] = stripCode(a[i]);
	}

	// a stack block that the callee copies or runs before it returns gets its own signature back afterwards
	void** restoreSlot = nullptr;
	void* restoreValue = nullptr;
	if ( (row->blockArg != 0) && (a[row->blockArg - 1] != 0) ) {
		BlockLiteral* block = (BlockLiteral*)a[row->blockArg - 1];
		if ( block->flags & kBlockIsGlobal ) {
			a[row->blockArg - 1] = (uint64_t)mirrorOfGlobalBlock(block);
		}
		else {
			if ( (block->flags & kBlockNeedsFree) == 0 ) {
				restoreSlot = &block->invoke;
				restoreValue = block->invoke;
			}
			block->invoke = (void*)stripCode((uint64_t)block->invoke);
		}
	}

	// the callee reads the struct during the call only, and the caller's can be read-only
	uint64_t structCopy[2];
	if ( (row->structArg != 0) && (a[row->structArg - 1] != 0) ) {
		memcpy(structCopy, (const void*)a[row->structArg - 1], sizeof(structCopy));
		structCopy[0] = stripCode(structCopy[0]);
		a[row->structArg - 1] = (uint64_t)structCopy;
	}

	uint64_t result = ((Call8)real)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);

	if ( restoreSlot != nullptr )
		*restoreSlot = restoreValue;
	switch ( row->ret ) {
		case ReturnFix::None:
			break;
		case ReturnFix::SignFunctionIA0:
			result = signFunctionIA0(result);
			break;
		case ReturnFix::ResignBlockInvoke:
			if ( result != 0 ) {
				BlockLiteral* block = (BlockLiteral*)result;
				// a global block is returned as it is, and its literal is the image's own, already signed
				if ( (block->flags & kBlockIsGlobal) == 0 )
					block->invoke = (void*)AdapterSign::signPointer(stripCode((uint64_t)block->invoke), &block->invoke, true, 0, 0);
			}
			break;
	}
	return result;
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
size_t emitCallThunk(uint32_t*, const AdapterRow*, uint64_t) { return 0; }
uint64_t callThunkHelperAddress() { return 0; }

#endif

} // namespace darling
} // namespace dyld3
