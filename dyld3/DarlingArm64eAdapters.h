// DARLING arm64e compat: callback-taking exports of Darling's plain arm64 libraries, as seen by arm64e importers.
//
// An arm64e image hands PAC-signed code pointers to a plain callee, which calls them with a plain BLR and faults
// (tests/arm64e-link/abi/README.md in the abi-probe branch). The loader knows at bind time that the importer is arm64e
// and that the resolved target is a plain image, so it binds a small thunk instead: it strips the signature on the
// way in and, for the few exports that hand a pointer back, signs it on the way out. A table of rows says which.
#ifndef DarlingArm64eAdapters_h
#define DarlingArm64eAdapters_h

#include <stddef.h>
#include <stdint.h>
#include <mach/machine.h>

namespace dyld3 {
namespace darling {

enum class AdapterStatus : uint8_t {
	Probed,			// an L2 ABI probe check runs this shape
	ShapeOnly,		// the same shape as a probed row, not run itself
	Unsupported		// the shape is known to matter and is not adapted; evidence says why
};

enum class ReturnFix : uint8_t {
	None,
	SignFunctionIA0,		// the result is a code pointer: sign it IA, discriminator 0 (0, 1 and -1 stay as they are)
	ResignBlockInvoke		// the result is a block: re-sign its invoke pointer for the block's address
};

// Argument numbers in the masks are counts from 0, one integer register each (at most 8, no FP or stack arguments).
struct AdapterRow {
	const char*		symbol;			// Mach-O name, with the leading underscore
	uint8_t			stripMask;		// bit i: argument i is a code pointer to strip
	uint8_t			blockArg;		// argument number + 1 of a block pointer whose invoke is stripped, 0 for none
	uint8_t			structArg;		// argument number + 1 of a pointer to a struct whose first word is a code pointer, 0 for none
	ReturnFix		ret;
	uint8_t			argCount;
	AdapterStatus	status;
	const char*		evidence;		// the probe check or the reason; never empty
};

inline bool cpusubtypeIsArm64e(cpu_subtype_t subtype)
{
	return (subtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E;
}

const AdapterRow* adapterRows(size_t* count);
const AdapterRow* findAdapterRow(const char* symbol);

// Why a table is malformed, or nullptr. Used on the built-in table by the host test and on synthetic ones.
const char* validateAdapterRows(const AdapterRow* rows, size_t count);

// What an arm64e importer should bind for `symbol` when the resolved target is at `target`: a thunk when the table has
// a row for it and the target is a plain image, otherwise `target`. An Unsupported row binds the target and warns.
// The caller has checked that the importer is arm64e. Callers hold dyld's lock.
uint64_t adaptedTarget(const char* symbol, uint64_t target, bool targetIsArm64e);

// DYLD_DARLING_ARM64E_ADAPTERS=off: bind the raw targets, as before the adapters existed.
void setAdaptersEnabled(bool enabled);

// The thunk bytes, exposed so a test can compare them with an assembler. Both return the number of words written.
size_t emitStripThunk(uint32_t* words, uint8_t stripMask, uint64_t real);
size_t emitCallThunk(uint32_t* words, const AdapterRow* row, uint64_t real);
uint64_t callThunkHelperAddress();

} // namespace darling
} // namespace dyld3

#endif
