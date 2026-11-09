// M0b: read-only feasibility scan of a split macOS dyld shared cache (arm64e).
//
// Counts, per image group, the facts that decide R0/R1/R2 of the shared-cache plan:
//   - svc #0x80 sites outside libsystem_kernel (raw Darwin syscalls that Darling cannot emulate)
//   - mrs Xt, TPIDRRO_EL0 sites, split into in-place rewritable (followed by AND-immediate on Xt)
//     and other
//   - bl/b instructions whose target is in another image, by destination group, with one level of
//     branch-island resolution (b, or adrp+add+br)
//   - free address gaps between mappings, branch pool count, patch info header numbers
// Prints counts and image names only; no cache content is copied. Linux/aarch64.
//
// Usage: m0b_scan <cache-dir> <base-name> [from-addr to-addr]   (addresses hex; restricts the scanned
// images to those whose __TEXT starts in [from,to); the image index always covers the whole cache)
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILES 32
#define MAX_MAPS 256
#define MAX_SECS 8

enum group { G_OTHER, G_KERNEL, G_SYS, G_OBJC, G_CXX, G_CF, G_COUNT };
static const char *gname[G_COUNT] = {"other", "libsystem_kernel", "libSystem-family", "libobjc", "libc++/abi", "CoreFoundation"};

struct mapping { uint64_t address, size, fileOffset; int file; };
struct cachefile { int fd; uint64_t size; char suffix[40]; };
struct sec { uint64_t addr, size; };
struct image {
    uint64_t addr, text_addr, text_size;
    char path[200];
    int group, nsec;
    struct sec secs[MAX_SECS];
    uint64_t svc, tsd_inplace, tsd_other, bl_out, b_out;
};

static struct cachefile files[MAX_FILES];
static int nfiles;
static struct mapping maps[MAX_MAPS];
static int nmaps;
static struct image *imgs;
static uint32_t nimgs;
static uint32_t *by_text; // image indices sorted by text_addr

static void die(const char *m) { fprintf(stderr, "m0b: %s (errno=%d %s)\n", m, errno, strerror(errno)); exit(1); }
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

static void pread_all(int fd, uint64_t off, void *buf, size_t len)
{
    size_t d = 0;
    while (d < len) {
        ssize_t n = pread(fd, (char *)buf + d, len - d, off + d);
        if (n <= 0) die("pread");
        d += (size_t)n;
    }
}

static const struct mapping *map_for(uint64_t a)
{
    for (int i = 0; i < nmaps; i++)
        if (a >= maps[i].address && a < maps[i].address + maps[i].size) return &maps[i];
    return NULL;
}

// read len bytes at cache address a; the range must lie inside one mapping
static int read_at(uint64_t a, void *buf, size_t len)
{
    const struct mapping *m = map_for(a);
    if (!m || a + len > m->address + m->size) return -1;
    pread_all(files[m->file].fd, m->fileOffset + (a - m->address), buf, len);
    return 0;
}

static int open_file(const char *dir, const char *base, const char *suffix)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/%s%s", dir, base, suffix);
    struct cachefile *cf = &files[nfiles];
    cf->fd = open(path, O_RDONLY | O_CLOEXEC);
    if (cf->fd < 0) die(path);
    struct stat st;
    fstat(cf->fd, &st);
    cf->size = (uint64_t)st.st_size;
    snprintf(cf->suffix, sizeof cf->suffix, "%s", suffix[0] ? suffix : "(main)");
    uint8_t h[0x200];
    pread_all(cf->fd, 0, h, sizeof h);
    uint32_t moff = rd32(h + 0x138), mcnt = rd32(h + 0x13c);
    for (uint32_t i = 0; i < mcnt; i++) {
        uint8_t e[56];
        pread_all(cf->fd, moff + (uint64_t)i * 56, e, sizeof e);
        if (nmaps >= MAX_MAPS) die("too many mappings");
        maps[nmaps++] = (struct mapping){rd64(e), rd64(e + 8), rd64(e + 16), nfiles};
    }
    return nfiles++;
}

static int classify(const char *p)
{
    if (!strcmp(p, "/usr/lib/system/libsystem_kernel.dylib")) return G_KERNEL;
    if (!strncmp(p, "/usr/lib/system/", 16) || !strcmp(p, "/usr/lib/libSystem.B.dylib")) return G_SYS;
    if (!strcmp(p, "/usr/lib/libobjc.A.dylib")) return G_OBJC;
    if (!strcmp(p, "/usr/lib/libc++.1.dylib") || !strcmp(p, "/usr/lib/libc++abi.dylib")) return G_CXX;
    if (strstr(p, "/CoreFoundation.framework/")) return G_CF;
    return G_OTHER;
}

static int cmp_text(const void *a, const void *b)
{
    uint64_t x = imgs[*(const uint32_t *)a].text_addr, y = imgs[*(const uint32_t *)b].text_addr;
    return x < y ? -1 : x > y;
}

// index of the image whose __TEXT contains a, or -1
static long image_for(uint64_t a)
{
    long lo = 0, hi = (long)nimgs - 1, r = -1;
    while (lo <= hi) {
        long mid = (lo + hi) / 2;
        if (imgs[by_text[mid]].text_addr <= a) { r = mid; lo = mid + 1; } else hi = mid - 1;
    }
    if (r < 0) return -1;
    struct image *im = &imgs[by_text[r]];
    return a < im->text_addr + im->text_size ? (long)by_text[r] : -1;
}

struct mach_seg { uint32_t cmd, cmdsize; char segname[16]; uint64_t vmaddr, vmsize, fileoff, filesize; uint32_t maxprot, initprot, nsects, flags; };
struct mach_sect { char sectname[16], segname[16]; uint64_t addr, size; uint32_t offset, align, reloff, nreloc, flags, r1, r2, r3; };

static void load_image(struct image *im)
{
    static uint8_t hdr[0x8000];
    size_t n = sizeof hdr;
    const struct mapping *m = map_for(im->addr);
    if (!m) die("image outside mappings");
    if (im->addr + n > m->address + m->size) n = m->address + m->size - im->addr;
    if (read_at(im->addr, hdr, n)) die("image header read");
    uint32_t ncmds = rd32(hdr + 16), sizeofcmds = rd32(hdr + 20);
    if (rd32(hdr) != 0xfeedfacf || 32 + sizeofcmds > n) die("bad image header");
    const uint8_t *c = hdr + 32;
    for (uint32_t i = 0; i < ncmds; i++, c += rd32(c + 4)) {
        if (rd32(c) != 0x19) continue;
        const struct mach_seg *s = (const struct mach_seg *)c;
        if (strcmp(s->segname, "__TEXT")) continue;
        im->text_addr = s->vmaddr;
        im->text_size = s->vmsize;
        const struct mach_sect *sec = (const struct mach_sect *)(c + sizeof *s);
        for (uint32_t k = 0; k < s->nsects && im->nsec < MAX_SECS; k++)
            if (sec[k].flags & 0x80000400u) im->secs[im->nsec++] = (struct sec){sec[k].addr, sec[k].size};
        break;
    }
}

// island resolution: returns the image index reached from island address t, or -1; sets *kind
static long resolve_island(uint64_t t, const char **kind)
{
    uint32_t w[4];
    if (read_at(t, w, sizeof w)) { *kind = "unreadable"; return -1; }
    if ((w[0] & 0xFC000000u) == 0x14000000u) { // b imm26
        int64_t off = ((int64_t)(int32_t)((w[0] & 0x03FFFFFFu) << 6) >> 6) * 4;
        long r = image_for(t + (uint64_t)off);
        *kind = r >= 0 ? "island:b" : "island:b->non-image";
        return r;
    }
    if ((w[0] & 0x9F000000u) == 0x90000000u && (w[1] & 0xFF800000u) == 0x91000000u) { // adrp; add
        int64_t imm = (int64_t)(((w[0] >> 29) & 3) | (((w[0] >> 5) & 0x7FFFF) << 2));
        imm = (imm << 43) >> 43; // sign-extend 21 bits
        uint64_t dst = (t & ~0xFFFULL) + (uint64_t)(imm << 12);
        uint32_t i12 = (w[1] >> 10) & 0xFFF;
        dst += (w[1] & 0x400000u) ? ((uint64_t)i12 << 12) : i12;
        if ((w[2] & 0xFFFFFC1Fu) == 0xD61F0000u) { // br xN
            long r = image_for(dst);
            *kind = r >= 0 ? "island:adrp+add+br" : "island:adrp+add+br->non-image";
            return r;
        }
        *kind = "island:got-indirect"; // adrp; add; ldr; braa style, target is read from a GOT slot
        return -1;
    }
    *kind = "island:other-shape";
    return -1;
}

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s <dir> <base> [from to]\n", argv[0]); return 2; }
    uint64_t from = 0, to = ~0ULL;
    if (argc >= 5) { from = strtoull(argv[3], 0, 16); to = strtoull(argv[4], 0, 16); }
    int mi = open_file(argv[1], argv[2], "");
    uint8_t h[0x400];
    pread_all(files[mi].fd, 0, h, sizeof h);
    uint32_t soff = rd32(h + 0x188), scnt = rd32(h + 0x18c);
    for (uint32_t i = 0; i < scnt; i++) {
        uint8_t e[56];
        pread_all(files[mi].fd, soff + (uint64_t)i * 56, e, sizeof e);
        char suf[33] = {0};
        memcpy(suf, e + 24, 32);
        open_file(argv[1], argv[2], suf);
    }
    uint32_t ioff = rd32(h + 0x1c0);
    nimgs = rd32(h + 0x1c4);
    imgs = calloc(nimgs, sizeof *imgs);
    by_text = calloc(nimgs, sizeof *by_text);
    uint8_t *itab = malloc((size_t)nimgs * 32);
    pread_all(files[mi].fd, ioff, itab, (size_t)nimgs * 32);
    const char *index_path = getenv("M0B_INDEX");
    FILE *xf = index_path ? fopen(index_path, "r") : NULL;
    if (xf) {
        // cached index (addresses, __TEXT extent, code sections, install name): no scattered header reads
        char line[1024];
        for (uint32_t i = 0; i < nimgs; i++) {
            if (!fgets(line, sizeof line, xf)) die("short index file");
            char *e = line;
            imgs[i].addr = strtoull(e, &e, 16);
            imgs[i].text_addr = strtoull(e, &e, 16);
            imgs[i].text_size = strtoull(e, &e, 16);
            imgs[i].nsec = (int)strtol(e, &e, 10);
            for (int k = 0; k < imgs[i].nsec; k++) {
                imgs[i].secs[k].addr = strtoull(e, &e, 16);
                imgs[i].secs[k].size = strtoull(e, &e, 16);
            }
            if (*e != '\t') die("bad index line");
            snprintf(imgs[i].path, sizeof imgs[i].path, "%s", e + 1);
            imgs[i].path[strcspn(imgs[i].path, "\n")] = 0;
            imgs[i].group = classify(imgs[i].path);
            by_text[i] = i;
        }
        fclose(xf);
    }
    for (uint32_t i = 0; xf == NULL && i < nimgs; i++) {
        imgs[i].addr = rd64(itab + (uint64_t)i * 32);
        size_t pl = sizeof imgs[i].path - 1;
        uint32_t po = rd32(itab + (uint64_t)i * 32 + 24);
        if (po + pl > files[mi].size) pl = files[mi].size - po;
        pread_all(files[mi].fd, po, imgs[i].path, pl);
        imgs[i].path[sizeof imgs[i].path - 1] = 0;
        imgs[i].group = classify(imgs[i].path);
        load_image(&imgs[i]);
        by_text[i] = i;
    }
    if (index_path && !xf) {
        FILE *wf = fopen(index_path, "w");
        if (!wf) die("write index");
        for (uint32_t i = 0; i < nimgs; i++) {
            fprintf(wf, "%" PRIx64 " %" PRIx64 " %" PRIx64 " %d", imgs[i].addr, imgs[i].text_addr, imgs[i].text_size, imgs[i].nsec);
            for (int k = 0; k < imgs[i].nsec; k++) fprintf(wf, " %" PRIx64 " %" PRIx64, imgs[i].secs[k].addr, imgs[i].secs[k].size);
            fprintf(wf, "\t%s\n", imgs[i].path);
        }
        fclose(wf);
    }
    qsort(by_text, nimgs, sizeof *by_text, cmp_text);
    printf("images %u, mappings %d, scan window [%#" PRIx64 ", %#" PRIx64 ")\n", nimgs, nmaps, from, to);
    if (from == 0) {
        // facts that do not need the text scan
        printf("branchPools: offset %#x count %u\n", rd32(h + 0x70), rd32(h + 0x74));
        uint64_t pa = rd64(h + 0x98), ps = rd64(h + 0xa0);
        printf("patchInfo: addr %#" PRIx64 " size %" PRIu64, pa, ps);
        uint8_t pi[64];
        if (pa && !read_at(pa, pi, sizeof pi))
            printf(" first words:");
        if (pa && !read_at(pa, pi, sizeof pi))
            for (int k = 0; k < 8; k++) printf(" %#" PRIx64, rd64(pi + 8 * k));
        printf("\n");
        // gaps between mappings, sorted by address
        int idx[MAX_MAPS];
        for (int i = 0; i < nmaps; i++) idx[i] = i;
        for (int i = 0; i < nmaps; i++)
            for (int j = i + 1; j < nmaps; j++)
                if (maps[idx[j]].address < maps[idx[i]].address) { int t = idx[i]; idx[i] = idx[j]; idx[j] = t; }
        printf("gaps between mappings (>0):\n");
        for (int i = 0; i + 1 < nmaps; i++) {
            uint64_t e = maps[idx[i]].address + maps[idx[i]].size, s = maps[idx[i + 1]].address;
            if (s > e) printf("  %#" PRIx64 "-%#" PRIx64 " (%" PRIu64 " bytes) between %s and %s\n", e, s, s - e,
                              files[maps[idx[i]].file].suffix, files[maps[idx[i + 1]].file].suffix);
        }
        long big = 0;
        for (int i = 0; i < nmaps; i++) if (maps[i].size > (256u << 20)) big++;
        printf("mappings larger than 256 MiB: %ld\n", big);
    }

    uint64_t cross[G_COUNT][G_COUNT] = {{0}}, cross_b[G_COUNT][G_COUNT] = {{0}};
    uint64_t isl[G_COUNT] = {0}, isl_kind_unres = 0, local_skipped = 0, insns = 0, nonimage = 0;
    uint64_t svc[G_COUNT] = {0}, tsd_in[G_COUNT] = {0}, tsd_ot[G_COUNT] = {0};
    uint64_t *to_img = calloc(nimgs, sizeof *to_img);
    const char *kinds[8]; uint64_t kcount[8] = {0}; int nk = 0;
    uint32_t scanned = 0;
    static uint32_t buf[1 << 20]; // 4 MiB chunks
    for (uint32_t ii = 0; ii < nimgs; ii++) {
        struct image *im = &imgs[ii];
        if (im->text_addr < from || im->text_addr >= to) continue;
        scanned++;
        for (int s = 0; s < im->nsec; s++) {
            for (uint64_t off = 0; off < im->secs[s].size; off += sizeof buf) {
                size_t len = im->secs[s].size - off < sizeof buf ? (size_t)(im->secs[s].size - off) : sizeof buf;
                len &= ~(size_t)3;
                uint64_t base = im->secs[s].addr + off;
                if (read_at(base, buf, len)) die("text read");
                for (size_t k = 0; k < len / 4; k++) {
                    uint32_t w = buf[k];
                    uint64_t pc = base + k * 4;
                    insns++;
                    if (w == 0xD4001001u) { im->svc++; svc[im->group]++; continue; }
                    if ((w & 0xFFFFFFE0u) == 0xD53BD060u) {
                        uint32_t rt = w & 31, nx = k + 1 < len / 4 ? buf[k + 1] : 0;
                        if ((nx & 0xFFC00000u) == 0x92400000u && (nx & 31) == rt && ((nx >> 5) & 31) == rt) {
                            im->tsd_inplace++; tsd_in[im->group]++; k++;
                        } else { im->tsd_other++; tsd_ot[im->group]++; }
                        continue;
                    }
                    uint32_t top = w & 0xFC000000u;
                    if (top != 0x94000000u && top != 0x14000000u) continue;
                    int is_bl = top == 0x94000000u;
                    int64_t d = ((int64_t)(int32_t)((w & 0x03FFFFFFu) << 6) >> 6) * 4;
                    uint64_t t = pc + (uint64_t)d;
                    if (t >= im->text_addr && t < im->text_addr + im->text_size) { local_skipped++; continue; }
                    long dst = image_for(t);
                    if (dst < 0) {
                        nonimage++;
                        const char *kind;
                        dst = resolve_island(t, &kind);
                        int ki = 0;
                        while (ki < nk && strcmp(kinds[ki], kind)) ki++;
                        if (ki == nk && nk < 8) kinds[nk++] = kind;
                        if (ki < 8) kcount[ki]++;
                        if (dst < 0) { isl_kind_unres++; continue; }
                        isl[imgs[dst].group]++;
                        if (dst == (long)ii) continue;
                    }
                    if (is_bl) { im->bl_out++; cross[im->group][imgs[dst].group]++; }
                    else { im->b_out++; cross_b[im->group][imgs[dst].group]++; }
                    to_img[dst]++;
                }
            }
        }
    }
    if (getenv("M0B_RAW")) { // machine-readable counters, summed by the driver across windows
        printf("C scanned_images %u\nC insns %" PRIu64 "\nC local %" PRIu64 "\nC nonimage %" PRIu64 "\nC unresolved %" PRIu64 "\n",
               scanned, insns, local_skipped, nonimage, isl_kind_unres);
        for (int g = 0; g < G_COUNT; g++) {
            printf("C svc %s %" PRIu64 "\nC tsd_inplace %s %" PRIu64 "\nC tsd_other %s %" PRIu64 "\nC isl_reach %s %" PRIu64 "\n",
                   gname[g], svc[g], gname[g], tsd_in[g], gname[g], tsd_ot[g], gname[g], isl[g]);
            for (int d = 0; d < G_COUNT; d++)
                printf("C bl %s>%s %" PRIu64 "\nC b %s>%s %" PRIu64 "\n", gname[g], gname[d], cross[g][d], gname[g], gname[d], cross_b[g][d]);
        }
        for (int i = 0; i < nk; i++) printf("C island_kind %s %" PRIu64 "\n", kinds[i], kcount[i]);
        for (uint32_t i = 0; i < nimgs; i++) {
            if (imgs[i].group != G_KERNEL && imgs[i].svc) printf("I svc %s\t%" PRIu64 "\n", imgs[i].path, imgs[i].svc);
            if (imgs[i].group != G_OTHER && to_img[i]) printf("I dst %s\t%" PRIu64 "\n", imgs[i].path, to_img[i]);
            if (imgs[i].tsd_inplace || imgs[i].tsd_other)
                printf("I tsd %s\t%" PRIu64 "/%" PRIu64 "\n", imgs[i].path, imgs[i].tsd_inplace, imgs[i].tsd_other);
        }
        return 0;
    }
    printf("scanned %u images, %" PRIu64 " instructions\n", scanned, insns);
    printf("svc #0x80 sites by group of owning image:");
    for (int g = 0; g < G_COUNT; g++) printf(" %s=%" PRIu64, gname[g], svc[g]);
    printf("\nmrs TPIDRRO_EL0 sites (in-place / other) by group:");
    for (int g = 0; g < G_COUNT; g++) printf(" %s=%" PRIu64 "/%" PRIu64, gname[g], tsd_in[g], tsd_ot[g]);
    printf("\ncross-image bl by (source group -> destination group), islands resolved one level:\n");
    for (int s = 0; s < G_COUNT; s++)
        for (int g = 1; g < G_COUNT; g++) if (cross[s][g]) printf("  bl  %s -> %s: %" PRIu64 "\n", gname[s], gname[g], cross[s][g]);
    for (int s = 0; s < G_COUNT; s++)
        for (int g = 1; g < G_COUNT; g++) if (cross_b[s][g]) printf("  b   %s -> %s: %" PRIu64 "\n", gname[s], gname[g], cross_b[s][g]);
    uint64_t other_dst = 0;
    for (int s = 0; s < G_COUNT; s++) other_dst += cross[s][G_OTHER] + cross_b[s][G_OTHER];
    printf("  (bl/b into other/non-replacement images: %" PRIu64 ")\n", other_dst);
    printf("targets outside any image __TEXT: %" PRIu64 "; island kinds:", nonimage);
    for (int i = 0; i < nk; i++) printf(" [%s]=%" PRIu64, kinds[i], kcount[i]);
    printf("; unresolved islands %" PRIu64 "; islands reaching images by group:", isl_kind_unres);
    for (int g = 0; g < G_COUNT; g++) printf(" %s=%" PRIu64, gname[g], isl[g]);
    printf("\nsame-image branches skipped: %" PRIu64 "\n", local_skipped);
    printf("images with svc #0x80 outside libsystem_kernel (name: count), top 15:\n");
    for (int n = 0; n < 15; n++) {
        long best = -1;
        for (uint32_t i = 0; i < nimgs; i++)
            if (imgs[i].group != G_KERNEL && imgs[i].svc && (best < 0 || imgs[i].svc > imgs[best].svc)) best = i;
        if (best < 0 || imgs[best].svc == 0) break;
        printf("  %s: %" PRIu64 "\n", imgs[best].path, imgs[best].svc);
        imgs[best].svc = 0;
    }
    printf("most called replacement-group images by cross-image bl/b (name: count), top 10:\n");
    for (int n = 0; n < 10; n++) {
        long best = -1;
        for (uint32_t i = 0; i < nimgs; i++)
            if (imgs[i].group != G_OTHER && to_img[i] && (best < 0 || to_img[i] > to_img[best])) best = i;
        if (best < 0) break;
        printf("  %s: %" PRIu64 "\n", imgs[best].path, to_img[best]);
        to_img[best] = 0;
    }
    return 0;
}
