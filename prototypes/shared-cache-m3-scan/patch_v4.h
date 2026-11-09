// Layout of the version-4 patch info of a split macOS dyld shared cache (arm64e, macOS 26 era),
// derived from the real data (array address spacing, index tiling, address checks and the slot words of
// 150k sampled locations; see M3-3.0b.md) and not from any Apple header: the local dyld tree (dyld-852)
// only has version 1.
//
// patchInfoAddr (cache header +0x98) points at struct pv4_header; every array and the export-name blob lie
// inside the patchInfoSize bytes that follow. Records are 4-byte aligned, little endian. The tables are
// organised per EXPORTING image (index = image index in the cache header):
//   patchTable[image]       pv4_image_patches: the image's clients (slice of `clients`) and its patchable exports
//                           (slice of `imageExports`); slices of consecutive images tile the arrays in order.
//   imageExports[]          pv4_image_export: implementation offset and name of one patchable export.
//   clients[]               pv4_client: an image that stores pointers to the exporter's symbols in its data
//                           (clientDylibIndex) and its slice of clientExports.
//   clientExports[]         pv4_client_export: which export (absolute index into imageExports, inside the exporter's
//                           slice) the client uses and the slice of `locations`.
//   locations[]             pv4_location: offset of the pointer from the CLIENT image's mach header plus its encoding.
//   gotClients[image]       pv4_got_clients: GOT usage of the same exporter (one record per image index): slice of
//                           gotClientExports. The GOT table names no client: the slots are the cache's coalesced GOT
//                           (one slot per bound symbol, shared by every image, so an image's own __auth_got is empty).
//   gotClientExports[]      pv4_got_client_export: absolute export index and slice of gotLocations.
//   gotLocations[]          pv4_got_location: 64-bit offset of the GOT slot from the cache base plus its encoding.
//   exportNames             NUL-terminated strings addressed by pv4_image_export.nameKind (low 28 bits).
#ifndef PATCH_V4_H
#define PATCH_V4_H
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#define PV4_VERSION 4

struct pv4_header {
    uint32_t patchTableVersion;     // 4
    uint32_t patchLocationVersion;  // 0
    uint64_t patchTableArrayAddr, patchTableArrayCount;
    uint64_t imageExportsArrayAddr, imageExportsArrayCount;
    uint64_t clientsArrayAddr, clientsArrayCount;
    uint64_t clientExportsArrayAddr, clientExportsArrayCount;
    uint64_t locationArrayAddr, locationArrayCount;
    uint64_t exportNamesAddr, exportNamesSize;
    uint64_t gotClientsArrayAddr, gotClientsArrayCount;
    uint64_t gotClientExportsArrayAddr, gotClientExportsArrayCount;
    uint64_t gotLocationArrayAddr, gotLocationArrayCount;
};
_Static_assert(sizeof(struct pv4_header) == 152, "pv4_header is 152 bytes (0x98)");

struct pv4_image_patches {
    uint32_t clientsStartIndex, clientsCount;  // slice of `clients`
    uint32_t exportsStartIndex, exportsCount;  // slice of `imageExports`
};
_Static_assert(sizeof(struct pv4_image_patches) == 16, "");

struct pv4_image_export {
    uint32_t dylibOffsetOfImpl;  // implementation = exporting image mach header + offset
    uint32_t nameKind;           // bits 0-27 offset into exportNames, bits 28-31 kind (observed 0: 336,681, 8: 239,791, 1: 4; meaning not determined)
};
_Static_assert(sizeof(struct pv4_image_export) == 8, "");
#define PV4_NAME_OFFSET(nk) ((nk) & 0x0fffffffu)
#define PV4_NAME_KIND(nk) ((nk) >> 28)

struct pv4_client {
    uint32_t clientDylibIndex;
    uint32_t exportsStartIndex, exportsCount;  // slice of `clientExports`
};
_Static_assert(sizeof(struct pv4_client) == 12, "");

struct pv4_client_export {
    uint32_t imageExportIndex;                    // absolute index into imageExports (inside the exporter's slice)
    uint32_t locationsStartIndex, locationsCount;  // slice of `locations`
};
_Static_assert(sizeof(struct pv4_client_export) == 12, "");

// Encoding word `flags` of a patch location (both location kinds), checked against the chain-encoded slot
// word of 128k sampled locations (see pv4_decode_flags):
//   bit 0       authenticated pointer
//   bits 1..7   high7: the pointer's top byte is high7 << 1 (unauthenticated pointers)
//   bit 8       set for ~0.1% of locations (meaning not determined; no effect on key, diversity, addend or target)
//   bits 9..13  addend (5 bits); for unauthenticated pointers bits 9..15 form a 7-bit addend
//   bit 14      uses address diversity (authenticated only)
//   bit 15      key, 1 = DA, 0 = IA (authenticated only)
//   bits 16..31 discriminator (authenticated only)
// The target stored in the slot is the exporter's implementation address plus the addend.
struct pv4_location {
    uint32_t dylibOffsetOfUse;  // address = client image mach header + offset
    uint32_t flags;
};
_Static_assert(sizeof(struct pv4_location) == 8, "");

struct pv4_got_clients {
    uint32_t exportsStartIndex, exportsCount;  // slice of `gotClientExports`
};
_Static_assert(sizeof(struct pv4_got_clients) == 8, "");

struct pv4_got_client_export {
    uint32_t imageExportIndex;                    // absolute index into imageExports (inside the exporter's slice)
    uint32_t locationsStartIndex, locationsCount;  // slice of `gotLocations`
};
_Static_assert(sizeof(struct pv4_got_client_export) == 12, "");

struct pv4_got_location {
    uint32_t cacheOffsetLo, cacheOffsetHi;  // 64-bit cache offset of the GOT slot (the high word is 0 or 1)
    uint32_t flags;
    uint32_t reserved;                      // 0 on the real cache
};
_Static_assert(sizeof(struct pv4_got_location) == 16, "");
_Static_assert(alignof(struct pv4_got_location) == 4 && alignof(struct pv4_location) == 4, "records are 4-byte aligned");


struct pv4_fixup {
    unsigned authenticated, high7, bit8, addend, usesAddressDiversity, key, discriminator;
};
static inline struct pv4_fixup pv4_decode_flags(uint32_t f)
{
    struct pv4_fixup d = {.authenticated = f & 1, .high7 = (f >> 1) & 0x7f, .bit8 = (f >> 8) & 1};
    if (d.authenticated) {
        d.addend = (f >> 9) & 0x1f;
        d.usesAddressDiversity = (f >> 14) & 1;
        d.key = (f >> 15) & 1;
        d.discriminator = f >> 16;
    } else {
        d.addend = (f >> 9) & 0x7f;
    }
    return d;
}

#endif
