// M3 task 3.0b: read-only interface scan of a split macOS dyld shared cache (arm64e).
// Facts only (names, offsets, sizes, counts, interface constants); no cache bytes are printed or stored.
// Usage: m3_scan <mode> <cache-dir> <base-name> <index.tsv> [args]
//   info                         image and mapping counts (smoke test)
//   hdr                          header flag word, mappings, patch info header words
//   patchcheck                   validate the version-4 patch table (patch_v4_check.h) against the cache
//   patchsample <n> [mask]       compare every nth location's slot word with the table (flag decoding evidence)
//   patchclient <path> [list] [n]  exporters/symbols whose patch locations lie in the image's data segments
//   patchexporters|patchexports <path>...  per exporting image: exports, clients, locations (and per export)
//   slots <path> | stubs <path> <addr> <size> | sections <path> | imgexports <path>   image structure facts
//   text <from> <to> [only-file] svc/TSD counts, commpage formations and offsets per image (windowed by __TEXT start)
//   dataq <path>...             commpage-like 8-byte words in data segments
#include "m3_cache.h"
#include "a64.h"
#include "trie.h"
#include "patch_v4_check.h"
#include "m3_util.h"
#include "mode_patch.h"
#include "mode_text.h"

int main(int argc, char **argv)
{
    if (argc < 5) { fprintf(stderr, "usage: %s <mode> <dir> <base> <index>\n", argv[0]); return 2; }
    static struct m3_cache c;
    m3_open_cache(&c, argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "info")) { printf("images %u, mappings %d, files %d\n", c.nimgs, c.nmaps, c.nfiles); return 0; }
    if (!strcmp(argv[1], "hdr")) return mode_hdr(&c);
    if (!strcmp(argv[1], "patchcheck")) return mode_patchcheck(&c);
    if (!strcmp(argv[1], "patchclient") && argc >= 6) return mode_patchclient(&c, argv[5], argc > 6 && !strcmp(argv[6], "list"), argc > 7 ? atoi(argv[7]) : 0);
    if (!strcmp(argv[1], "patchsample") && argc >= 6) return mode_patchsample(&c, (size_t)atol(argv[5]), argc > 6 ? (uint32_t)strtoul(argv[6], 0, 16) : 0);
    if (!strcmp(argv[1], "patchexporters") && argc >= 6) return mode_patchexporters(&c, argc - 5, argv + 5, 0);
    if (!strcmp(argv[1], "patchexports") && argc >= 6) return mode_patchexporters(&c, argc - 5, argv + 5, 1);
    if (!strcmp(argv[1], "slots") && argc >= 6) return mode_slots(&c, argv[5]);
    if (!strcmp(argv[1], "sections") && argc >= 6) return mode_sections(&c, argv[5]);
    if (!strcmp(argv[1], "stubs") && argc >= 8) return mode_stubs(&c, argv[5], strtoull(argv[6], 0, 16), strtoull(argv[7], 0, 16));
    if (!strcmp(argv[1], "text") && argc >= 7) return mode_text(&c, strtoull(argv[5], 0, 16), strtoull(argv[6], 0, 16), argc > 7 ? argv[7] : NULL);
    if (!strcmp(argv[1], "imgexports") && argc >= 6) return mode_imgexports(&c, argv[5]);
    if (!strcmp(argv[1], "dataq") && argc >= 6) return mode_dataq(&c, argc - 5, argv + 5);
    fprintf(stderr, "unknown mode %s\n", argv[1]);
    return 2;
}

