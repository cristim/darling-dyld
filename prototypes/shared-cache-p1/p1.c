// P1: standalone prototype for native dyld shared-cache support.
//
// Maps a split macOS dyld shared cache (main file + sub-caches) read-only at its preferred addresses,
// locates one image through the image table, prints its Mach-O header and load commands from the
// mapped memory, and decodes slide-info v5 chains for that image's writable segments.
//
// Linux/aarch64 only. Reads the cache as private input; prints facts, never copies content.
// Layout offsets are those of the split-cache header (verified against a macOS 26.6 arm64e cache).
//
// Usage: p1 <cache-dir> <base-name> [image-path]
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

// --- cache header offsets (dyld_cache_header, split-cache generation) ---
enum {
    H_MAPPING_OFF = 0x10,      // u32 old-style mapping array offset, count at +4
    H_UUID = 0x58,             // u8[16]
    H_REGION_START = 0xe0,     // u64 sharedRegionStart
    H_REGION_SIZE = 0xe8,      // u64 sharedRegionSize
    H_MAPSLIDE_OFF = 0x138,    // u32 mappingWithSlideOffset, count at +4
    H_SUBCACHE_OFF = 0x188,    // u32 subCacheArrayOffset, count at +4
    H_IMAGES_OFF = 0x1c0,      // u32 imagesOffset, count at +4
};
#define SUBCACHE_ENTRY_SIZE 56  // uuid[16], cacheVMOffset u64, fileSuffix char[32]
#define MAPSLIDE_ENTRY_SIZE 56  // address, size, fileOffset, slideInfoFileOffset, slideInfoFileSize, flags (u64), maxProt, initProt (u32)
#define IMAGE_ENTRY_SIZE 32     // address u64, modTime u64, inode u64, pathFileOffset u32, pad u32
#define MAX_FILES 32
#define MAX_MAPS 256

struct mapping {
    uint64_t address, size, fileOffset, slideOff, slideSize, flags;
    uint32_t maxProt, initProt;
    int file;
    int mapped;
};

struct cachefile {
    char path[1024];
    char suffix[40];
    int fd;
    uint64_t size;
    uint8_t uuid[16];
};

static struct cachefile files[MAX_FILES];
static int nfiles;
static struct mapping maps[MAX_MAPS];
static int nmaps;
static uint64_t region_start, region_size;

static void die(const char *msg)
{
    fprintf(stderr, "p1: %s (errno=%d %s)\n", msg, errno, strerror(errno));
    exit(1);
}

static void pread_all(int fd, uint64_t off, void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread(fd, (char *)buf + done, len - done, off + done);
        if (n <= 0)
            die("pread");
        done += (size_t)n;
    }
}

static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

static long rss_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long kb = -1;
    while (f && fgets(line, sizeof line, f))
        if (sscanf(line, "VmRSS: %ld kB", &kb) == 1)
            break;
    if (f)
        fclose(f);
    return kb;
}

static int open_cachefile(const char *dir, const char *base, const char *suffix)
{
    if (nfiles >= MAX_FILES)
        die("too many cache files");
    struct cachefile *cf = &files[nfiles];
    snprintf(cf->path, sizeof cf->path, "%s/%s%s", dir, base, suffix);
    snprintf(cf->suffix, sizeof cf->suffix, "%s", suffix[0] ? suffix : "(main)");
    cf->fd = open(cf->path, O_RDONLY | O_CLOEXEC);
    if (cf->fd < 0) {
        fprintf(stderr, "p1: open %s failed\n", cf->path);
        die("open");
    }
    struct stat st;
    if (fstat(cf->fd, &st) != 0)
        die("fstat");
    cf->size = (uint64_t)st.st_size;
    uint8_t hdr[0x200];
    pread_all(cf->fd, 0, hdr, sizeof hdr);
    if (memcmp(hdr, "dyld_v1", 7) != 0)
        die("bad cache magic");
    memcpy(cf->uuid, hdr + H_UUID, 16);

    uint32_t moff = rd32(hdr + H_MAPSLIDE_OFF), mcnt = rd32(hdr + H_MAPSLIDE_OFF + 4);
    for (uint32_t i = 0; i < mcnt; i++) {
        uint8_t e[MAPSLIDE_ENTRY_SIZE];
        pread_all(cf->fd, moff + (uint64_t)i * MAPSLIDE_ENTRY_SIZE, e, sizeof e);
        if (nmaps >= MAX_MAPS)
            die("too many mappings");
        struct mapping *m = &maps[nmaps++];
        m->address = rd64(e + 0);
        m->size = rd64(e + 8);
        m->fileOffset = rd64(e + 16);
        m->slideOff = rd64(e + 24);
        m->slideSize = rd64(e + 32);
        m->flags = rd64(e + 40);
        m->maxProt = rd32(e + 48);
        m->initProt = rd32(e + 52);
        m->file = nfiles;
    }
    return nfiles++;
}

static const struct mapping *mapping_for(uint64_t addr)
{
    for (int i = 0; i < nmaps; i++)
        if (addr >= maps[i].address && addr < maps[i].address + maps[i].size)
            return &maps[i];
    return NULL;
}

// --- Mach-O (public, stable layout; minimal local copies) ---
struct mh64 { uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved; };
struct lc { uint32_t cmd, cmdsize; };
struct seg64 {
    uint32_t cmd, cmdsize; char segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t maxprot, initprot, nsects, flags;
};
#define LC_SEGMENT_64 0x19
#define LC_ID_DYLIB 0xd
#define LC_LOAD_DYLIB 0xc
#define LC_UUID 0x1b
#define LC_BUILD_VERSION 0x32
#define LC_REEXPORT_DYLIB (0x1f | 0x80000000)
#define LC_LOAD_WEAK_DYLIB (0x18 | 0x80000000)
#define LC_LOAD_UPWARD_DYLIB (0x23 | 0x80000000)

static const char *lcname(uint32_t c)
{
    switch (c) {
    case LC_SEGMENT_64: return "LC_SEGMENT_64";
    case LC_ID_DYLIB: return "LC_ID_DYLIB";
    case LC_LOAD_DYLIB: return "LC_LOAD_DYLIB";
    case LC_REEXPORT_DYLIB: return "LC_REEXPORT_DYLIB";
    case LC_LOAD_WEAK_DYLIB: return "LC_LOAD_WEAK_DYLIB";
    case LC_LOAD_UPWARD_DYLIB: return "LC_LOAD_UPWARD_DYLIB";
    case LC_UUID: return "LC_UUID";
    case LC_BUILD_VERSION: return "LC_BUILD_VERSION";
    case 0x2: return "LC_SYMTAB";
    case 0xb: return "LC_DYSYMTAB";
    case 0x26: return "LC_FUNCTION_STARTS";
    case 0x29: return "LC_DATA_IN_CODE";
    case 0x2a: return "LC_SOURCE_VERSION";
    case 0x1d: return "LC_CODE_SIGNATURE";
    case 0x2b: return "LC_DYLIB_CODE_SIGN_DRS";
    case 0x1e: return "LC_SEGMENT_SPLIT_INFO";
    case 0x80000034: return "LC_DYLD_EXPORTS_TRIE";
    case 0x80000033: return "LC_DYLD_CHAINED_FIXUPS";
    case 0x22: case 0x80000022: return "LC_DYLD_INFO(_ONLY)";
    default: return "LC_?";
    }
}

// --- slide info v5 ---
struct slide5 {
    uint32_t version, page_size, page_starts_count, pad;
    uint64_t value_add;
};

struct stats {
    uint64_t fixups, auth, regular, in_region, in_mapping, out, chain_err, addrdiv, keyda;
};

static void pac_demo(uint64_t target, uint64_t loc, unsigned key_da, unsigned addrdiv, unsigned diversity)
{
    uint64_t mod = diversity;
    if (addrdiv)
        mod = (loc & 0x0000ffffffffffffULL) | ((uint64_t)diversity << 48);
    uint64_t s = target, a;
    if (key_da)
        __asm__ volatile("pacda %0, %1" : "+r"(s) : "r"(mod));
    else
        __asm__ volatile("pacia %0, %1" : "+r"(s) : "r"(mod));
    a = s;
    if (key_da)
        __asm__ volatile("autda %0, %1" : "+r"(a) : "r"(mod));
    else
        __asm__ volatile("autia %0, %1" : "+r"(a) : "r"(mod));
    printf("      pac demo (process key %s, modifier %#" PRIx64 "): signed %#" PRIx64 " -> auth %#" PRIx64 " roundtrip=%s\n",
           key_da ? "DA" : "IA", mod, s, a, a == target ? "ok" : "FAIL");
}

static void decode_segment(const struct seg64 *sg, struct stats *st, int *shown_pages, int max_show_pages, int *pac_shown)
{
    const struct mapping *m = mapping_for(sg->vmaddr);
    if (!m || m->slideSize == 0) {
        printf("  %-16s %#" PRIx64 "+%#" PRIx64 ": no slide info (mapping %s)\n", sg->segname, sg->vmaddr, sg->vmsize,
               m ? "has none" : "not found");
        return;
    }
    struct cachefile *cf = &files[m->file];
    uint8_t *si = malloc(m->slideSize);
    if (!si)
        die("malloc");
    pread_all(cf->fd, m->slideOff, si, m->slideSize);
    struct slide5 s5;
    memcpy(&s5, si, sizeof s5);
    if (s5.version != 5) {
        printf("  %-16s slide info version %u (decoder handles 5 only)\n", sg->segname, s5.version);
        free(si);
        return;
    }
    const uint16_t *page_starts = (const uint16_t *)(si + sizeof s5);
    printf("  %-16s %#" PRIx64 "+%#" PRIx64 " in %s mapping %#" PRIx64 ": slide v5 page_size=%#x pages=%u value_add=%#" PRIx64 "\n",
           sg->segname, sg->vmaddr, sg->vmsize, cf->suffix, m->address, s5.page_size, s5.page_starts_count, s5.value_add);
    uint64_t first = sg->vmaddr & ~(uint64_t)(s5.page_size - 1);
    for (uint64_t pa = first; pa < sg->vmaddr + sg->vmsize; pa += s5.page_size) {
        uint64_t idx = (pa - m->address) / s5.page_size;
        if (idx >= s5.page_starts_count) {
            st->chain_err++;
            continue;
        }
        uint16_t start = page_starts[idx];
        if (start == 0xFFFF)
            continue;
        int show = *shown_pages < max_show_pages;
        int page_printed = 0;
        uint32_t off = start;
        int shown_ptrs = 0;
        for (;;) {
            if (off + 8 > s5.page_size) {
                st->chain_err++;
                break;
            }
            uint64_t loc = pa + off;
            if (loc >= m->address + m->size) {
                st->chain_err++;
                break;
            }
            uint64_t raw = rd64((const uint8_t *)loc);
            unsigned next0 = (unsigned)((raw >> 52) & 0x7ff);
            // pages are shared with neighbouring images: walk the whole chain, count only this segment's slots
            if (loc < sg->vmaddr || loc >= sg->vmaddr + sg->vmsize) {
                if (next0 == 0)
                    break;
                off += next0 * 8;
                continue;
            }
            if (show && !page_printed) {
                printf("    page %#" PRIx64 " (index %" PRIu64 ") first chain start +%#x\n", pa, idx, start);
                page_printed = 1;
                (*shown_pages)++;
            }
            uint64_t runtime_off = raw & 0x3ffffffffULL;
            unsigned next = (unsigned)((raw >> 52) & 0x7ff);
            unsigned auth = (unsigned)(raw >> 63);
            uint64_t target = s5.value_add + runtime_off;
            unsigned high8 = 0, div = 0, addrdiv = 0, keyda = 0;
            if (auth) {
                div = (unsigned)((raw >> 34) & 0xffff);
                addrdiv = (unsigned)((raw >> 50) & 1);
                keyda = (unsigned)((raw >> 51) & 1);
                st->auth++;
                st->addrdiv += addrdiv;
                st->keyda += keyda;
            } else {
                high8 = (unsigned)((raw >> 34) & 0xff);
                target |= (uint64_t)high8 << 56;
                st->regular++;
            }
            st->fixups++;
            uint64_t t = target & 0x00ffffffffffffffULL;
            const struct mapping *tm = mapping_for(t);
            if (t >= region_start && t < region_start + region_size)
                st->in_region++;
            else
                st->out++;
            if (tm)
                st->in_mapping++;
            if (show && shown_ptrs < 6) {
                printf("      @%#" PRIx64 " raw=%#018" PRIx64 " -> target %#" PRIx64 " %s", loc, raw, target,
                       auth ? "auth" : "plain");
                if (auth)
                    printf(" div=%#x addrDiv=%u key=%s", div, addrdiv, keyda ? "DA" : "IA");
                else
                    printf(" high8=%#x", high8);
                printf(" [%s]\n", tm ? files[tm->file].suffix : "outside mappings");
                shown_ptrs++;
                if (auth && *pac_shown < 2 && tm) {
                    pac_demo(t, loc, keyda, addrdiv, div);
                    (*pac_shown)++;
                }
            }
            if (next == 0)
                break;
            off += next * 8;
        }
    }
    free(si);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <cache-dir> <base-name> [image-path]\n", argv[0]);
        return 2;
    }
    const char *dir = argv[1], *base = argv[2];
    const char *want = argc > 3 ? argv[3] : "/System/Library/PrivateFrameworks/Recap.framework/Versions/A/Recap";

    // 1. main file header, sub-cache array
    int mainidx = open_cachefile(dir, base, "");
    uint8_t *mainhdr = malloc(0x400);
    pread_all(files[mainidx].fd, 0, mainhdr, 0x400);
    char magic[17] = {0};
    memcpy(magic, mainhdr, 16);
    region_start = rd64(mainhdr + H_REGION_START);
    region_size = rd64(mainhdr + H_REGION_SIZE);
    printf("main: magic '%s' size %" PRIu64 " region %#" PRIx64 "+%#" PRIx64 "\n", magic, files[mainidx].size, region_start, region_size);

    uint32_t soff = rd32(mainhdr + H_SUBCACHE_OFF), scnt = rd32(mainhdr + H_SUBCACHE_OFF + 4);
    printf("sub-caches: %u at %#x\n", scnt, soff);
    for (uint32_t i = 0; i < scnt; i++) {
        uint8_t e[SUBCACHE_ENTRY_SIZE];
        pread_all(files[mainidx].fd, soff + (uint64_t)i * SUBCACHE_ENTRY_SIZE, e, sizeof e);
        char suffix[33] = {0};
        memcpy(suffix, e + 24, 32);
        int fi = open_cachefile(dir, base, suffix);
        int uuid_ok = memcmp(e, files[fi].uuid, 16) == 0;
        printf("  [%2u] %-22s vmOffset %#10" PRIx64 " size %11" PRIu64 " uuid %s\n", i, suffix, rd64(e + 16), files[fi].size,
               uuid_ok ? "matches header" : "MISMATCH");
        if (!uuid_ok)
            die("sub-cache uuid mismatch");
    }
    printf("mappings across %d files: %d\n", nfiles, nmaps);

    // 2. map every mapping read-only at its preferred address
    long rss0 = rss_kb();
    int mapfail = 0;
    for (int i = 0; i < nmaps; i++) {
        struct mapping *m = &maps[i];
        struct cachefile *cf = &files[m->file];
        if (m->fileOffset + m->size > cf->size)
            printf("  warn: mapping %d (%s) extends past file end\n", i, cf->suffix);
        void *p = mmap((void *)m->address, m->size, PROT_READ, MAP_PRIVATE | MAP_FIXED_NOREPLACE, cf->fd, (off_t)m->fileOffset);
        if (p == MAP_FAILED) {
            printf("  map %2d %-22s %#" PRIx64 "+%#" PRIx64 " prot %u/%u FAILED errno=%d %s\n", i, cf->suffix, m->address, m->size,
                   m->maxProt, m->initProt, errno, strerror(errno));
            mapfail++;
        } else if ((uint64_t)p != m->address) {
            printf("  map %2d landed at %p, expected %#" PRIx64 "\n", i, p, m->address);
            mapfail++;
        } else {
            m->mapped = 1;
        }
    }
    printf("mapped %d of %d mappings read-only at preferred addresses (%d failures); RSS %ld kB -> %ld kB\n", nmaps - mapfail, nmaps,
           mapfail, rss0, rss_kb());
    if (mapfail)
        return 3;

    // 3. image table (in the main file), find the wanted image
    uint32_t ioff = rd32(mainhdr + H_IMAGES_OFF), icnt = rd32(mainhdr + H_IMAGES_OFF + 4);
    uint8_t *itab = malloc((size_t)icnt * IMAGE_ENTRY_SIZE);
    pread_all(files[mainidx].fd, ioff, itab, (size_t)icnt * IMAGE_ENTRY_SIZE);
    int found = -1;
    uint64_t addr = 0;
    for (uint32_t i = 0; i < icnt && found < 0; i++) {
        uint32_t po = rd32(itab + (uint64_t)i * IMAGE_ENTRY_SIZE + 24);
        char path[512];
        size_t n = sizeof path - 1;
        if (po + n > files[mainidx].size)
            n = files[mainidx].size - po;
        pread_all(files[mainidx].fd, po, path, n);
        path[n] = 0;
        if (strcmp(path, want) == 0) {
            found = (int)i;
            addr = rd64(itab + (uint64_t)i * IMAGE_ENTRY_SIZE);
        }
    }
    printf("images: %u at %#x\n", icnt, ioff);
    if (found < 0) {
        printf("image '%s' not found\n", want);
        return 4;
    }
    const struct mapping *im = mapping_for(addr);
    printf("image %d: %s at %#" PRIx64 " in sub-cache %s\n", found, want, addr, im ? files[im->file].suffix : "?");

    // 4. Mach-O header and load commands from mapped memory
    const struct mh64 *mh = (const struct mh64 *)addr;
    printf("mach_header_64: magic %#x cputype %#x cpusubtype %#x filetype %u ncmds %u sizeofcmds %u flags %#x\n", mh->magic, mh->cputype,
           mh->cpusubtype, mh->filetype, mh->ncmds, mh->sizeofcmds, mh->flags);
    if (mh->magic != 0xfeedfacf)
        die("not a 64-bit Mach-O at image address");
    struct stats total = {0};
    struct seg64 segs[32];
    int nsegs = 0;
    const uint8_t *cmd = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct lc *c = (const struct lc *)cmd;
        printf("  cmd %2u %-24s size %u", i, lcname(c->cmd), c->cmdsize);
        if (c->cmd == LC_SEGMENT_64) {
            const struct seg64 *s = (const struct seg64 *)cmd;
            printf("  %-16s vm %#" PRIx64 "+%#" PRIx64 " fileoff %#" PRIx64 " prot %u/%u nsects %u", s->segname, s->vmaddr, s->vmsize,
                   s->fileoff, s->maxprot, s->initprot, s->nsects);
            if (nsegs < 32)
                segs[nsegs++] = *s;
        } else if (c->cmd == LC_ID_DYLIB || c->cmd == LC_LOAD_DYLIB || c->cmd == LC_REEXPORT_DYLIB || c->cmd == LC_LOAD_WEAK_DYLIB ||
                   c->cmd == LC_LOAD_UPWARD_DYLIB) {
            uint32_t nameoff = *(const uint32_t *)(cmd + 8);
            printf("  %s", (const char *)(cmd + nameoff));
        } else if (c->cmd == LC_UUID) {
            printf("  ");
            for (int k = 0; k < 16; k++)
                printf("%02x", cmd[8 + k]);
        } else if (c->cmd == LC_BUILD_VERSION) {
            printf("  platform %u minos %#x sdk %#x", *(const uint32_t *)(cmd + 8), *(const uint32_t *)(cmd + 12),
                   *(const uint32_t *)(cmd + 16));
        }
        printf("\n");
        cmd += c->cmdsize;
    }

    // 5. slide info v5 for the image's segments
    printf("slide-info decode (segments owned by a mapping with slide info):\n");
    int shown_pages = 0, pac_shown = 0;
    for (int i = 0; i < nsegs; i++)
        if (segs[i].initprot & 2)
            decode_segment(&segs[i], &total, &shown_pages, 4, &pac_shown);
    printf("totals: fixups %" PRIu64 " (auth %" PRIu64 ", plain %" PRIu64 "), in cache region %" PRIu64 ", inside a mapping %" PRIu64
           ", outside region %" PRIu64 ", chain errors %" PRIu64 ", addrDiv %" PRIu64 ", DA-key %" PRIu64 "\n",
           total.fixups, total.auth, total.regular, total.in_region, total.in_mapping, total.out, total.chain_err, total.addrdiv,
           total.keyda);
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("process maxrss %ld kB\n", ru.ru_maxrss);
    return total.fixups > 0 && total.out == 0 && total.chain_err == 0 ? 0 : 5;
}
