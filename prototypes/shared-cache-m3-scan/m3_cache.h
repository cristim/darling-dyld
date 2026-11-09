// Read-only access to a split macOS dyld shared cache for the M3 3.0b interface scan.
// Mapping table, pread-based reads and the image index are taken from
// prototypes/shared-cache-p1/m0b_scan.c (same index file format) so the scanners agree on addresses.
// Nothing here writes cache bytes anywhere; callers keep bytes in process memory only.
#ifndef M3_CACHE_H
#define M3_CACHE_H
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

#define M3_MAX_FILES 32
#define M3_MAX_MAPS 256
#define M3_MAX_SECS 8

struct m3_mapping { uint64_t address, size, fileOffset, slideInfoSize, flags; uint32_t initProt; int file; }; // dyld_cache_mapping_and_slide_info (56 bytes)
struct m3_sec { uint64_t addr, size; };
struct m3_image {
    uint64_t addr, text_addr, text_size;
    char path[200];
    int nsec;
    struct m3_sec secs[M3_MAX_SECS];
};

struct m3_cache {
    int fds[M3_MAX_FILES];
    uint64_t fsize[M3_MAX_FILES];
    int nfiles;
    struct m3_mapping maps[M3_MAX_MAPS];
    int nmaps;
    struct m3_image *imgs;
    uint32_t nimgs;
    uint8_t header[0x400]; // main file header, first 1 KiB
};

static inline void m3_die(const char *m)
{
    fprintf(stderr, "m3: %s (errno=%d %s)\n", m, errno, strerror(errno));
    exit(1);
}
static inline uint32_t m3_rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static inline uint64_t m3_rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

static inline void m3_pread_all(int fd, uint64_t off, void *buf, size_t len)
{
    size_t d = 0;
    while (d < len) {
        ssize_t n = pread(fd, (char *)buf + d, len - d, off + d);
        if (n <= 0) m3_die("pread");
        d += (size_t)n;
    }
}

static inline const struct m3_mapping *m3_map_for(const struct m3_cache *c, uint64_t a)
{
    for (int i = 0; i < c->nmaps; i++)
        if (a >= c->maps[i].address && a < c->maps[i].address + c->maps[i].size) return &c->maps[i];
    return NULL;
}

// read len bytes at cache address a; the range must lie inside one mapping; 0 on success
static inline int m3_read_at(const struct m3_cache *c, uint64_t a, void *buf, size_t len)
{
    const struct m3_mapping *m = m3_map_for(c, a);
    if (!m || a + len > m->address + m->size) return -1;
    m3_pread_all(c->fds[m->file], m->fileOffset + (a - m->address), buf, len);
    return 0;
}

static inline int m3_open_file(struct m3_cache *c, const char *dir, const char *base, const char *suffix)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/%s%s", dir, base, suffix);
    int i = c->nfiles;
    c->fds[i] = open(path, O_RDONLY | O_CLOEXEC);
    if (c->fds[i] < 0) m3_die(path);
    struct stat st;
    fstat(c->fds[i], &st);
    c->fsize[i] = (uint64_t)st.st_size;
    uint8_t h[0x200];
    m3_pread_all(c->fds[i], 0, h, sizeof h);
    uint32_t moff = m3_rd32(h + 0x138), mcnt = m3_rd32(h + 0x13c);
    for (uint32_t k = 0; k < mcnt; k++) {
        uint8_t e[56];
        m3_pread_all(c->fds[i], moff + (uint64_t)k * 56, e, sizeof e);
        if (c->nmaps >= M3_MAX_MAPS) m3_die("too many mappings");
        c->maps[c->nmaps++] = (struct m3_mapping){m3_rd64(e), m3_rd64(e + 8), m3_rd64(e + 16), m3_rd64(e + 32), m3_rd64(e + 40), m3_rd32(e + 52), i};
    }
    return c->nfiles++;
}

// load the index file written by m0b_scan (image address, __TEXT extent, code sections, install name)
static inline void m3_load_index(struct m3_cache *c, const char *index_path)
{
    FILE *xf = fopen(index_path, "r");
    if (!xf) m3_die(index_path);
    char line[1024];
    for (uint32_t i = 0; i < c->nimgs; i++) {
        if (!fgets(line, sizeof line, xf)) m3_die("short index file");
        char *e = line;
        struct m3_image *im = &c->imgs[i];
        im->addr = strtoull(e, &e, 16);
        im->text_addr = strtoull(e, &e, 16);
        im->text_size = strtoull(e, &e, 16);
        im->nsec = (int)strtol(e, &e, 10);
        if (im->nsec < 0 || im->nsec > M3_MAX_SECS) m3_die("bad index line (nsec)");
        for (int k = 0; k < im->nsec; k++) {
            im->secs[k].addr = strtoull(e, &e, 16);
            im->secs[k].size = strtoull(e, &e, 16);
        }
        if (*e != '\t') m3_die("bad index line");
        snprintf(im->path, sizeof im->path, "%s", e + 1);
        im->path[strcspn(im->path, "\n")] = 0;
    }
    fclose(xf);
}

// open the main file plus every sub-cache it lists and load the image index
static inline void m3_open_cache(struct m3_cache *c, const char *dir, const char *base, const char *index_path)
{
    memset(c, 0, sizeof *c);
    int mi = m3_open_file(c, dir, base, "");
    m3_pread_all(c->fds[mi], 0, c->header, sizeof c->header);
    uint32_t soff = m3_rd32(c->header + 0x188), scnt = m3_rd32(c->header + 0x18c);
    for (uint32_t i = 0; i < scnt; i++) {
        uint8_t e[56];
        char suf[33] = {0};
        m3_pread_all(c->fds[mi], soff + (uint64_t)i * 56, e, sizeof e);
        memcpy(suf, e + 24, 32);
        m3_open_file(c, dir, base, suf);
    }
    c->nimgs = m3_rd32(c->header + 0x1c4);
    c->imgs = calloc(c->nimgs, sizeof *c->imgs);
    if (!c->imgs) m3_die("calloc");
    m3_load_index(c, index_path);
}

static inline long m3_find_image(const struct m3_cache *c, const char *path)
{
    for (uint32_t i = 0; i < c->nimgs; i++)
        if (!strcmp(c->imgs[i].path, path)) return (long)i;
    return -1;
}

#endif
