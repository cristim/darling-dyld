// M3 task 3.0b: read-only interface scan of a split macOS dyld shared cache (arm64e).
// Facts only (names, offsets, sizes, counts, interface constants); no cache bytes are printed or stored.
// Usage: m3_scan <mode> <cache-dir> <base-name> <index.tsv> [args]
//   info                         image and mapping counts (smoke test)
#include "m3_cache.h"
#include "trie.h"
#include "patch_v4_check.h"
#include "m3_util.h"

int main(int argc, char **argv)
{
    if (argc < 5) { fprintf(stderr, "usage: %s <mode> <dir> <base> <index>\n", argv[0]); return 2; }
    static struct m3_cache c;
    m3_open_cache(&c, argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "info")) { printf("images %u, mappings %d, files %d\n", c.nimgs, c.nmaps, c.nfiles); return 0; }
    fprintf(stderr, "unknown mode %s\n", argv[1]);
    return 2;
}

