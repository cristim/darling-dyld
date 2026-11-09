// Shared helpers of the 3.0b scanner modes: patch blob loading, the patch table environment, image segment
// extents and the (export name, GOT slot) lookup tables. Included by m3_scan.c only.
#ifndef M3_UTIL_H
#define M3_UTIL_H
// read the whole patch info blob into memory (sequential 8 MiB reads), returns malloc'd buffer
static uint8_t *load_patch_blob(struct m3_cache *c, uint64_t *base, uint64_t *size)
{
    *base = m3_rd64(c->header + 0x98);
    *size = m3_rd64(c->header + 0xa0);
    uint8_t *buf = malloc(*size);
    if (!buf) m3_die("malloc patch blob");
    for (uint64_t off = 0; off < *size; off += 8u << 20) {
        size_t n = *size - off < (8u << 20) ? (size_t)(*size - off) : (8u << 20);
        if (m3_read_at(c, *base + off, buf + off, n)) m3_die("patch blob read");
    }
    return buf;
}


// patch table environment from the cache: image addresses and mapped data ranges (mappings carrying slide info)
static struct pv4_env make_env(const struct m3_cache *c)
{
    static struct pv4_range data[M3_MAX_MAPS];
    struct pv4_env env = {.nimages = c->nimgs, .cache_base = c->maps[0].address, .data = data};
    uint64_t *addr = malloc(c->nimgs * sizeof *addr);
    if (!addr) m3_die("malloc");
    for (uint32_t i = 0; i < c->nimgs; i++) addr[i] = c->imgs[i].addr;
    env.image_addr = addr;
    for (int i = 0; i < c->nmaps; i++)
        if (c->maps[i].slideInfoSize) data[env.ndata++] = (struct pv4_range){c->maps[i].address, c->maps[i].address + c->maps[i].size};
    return env;
}


struct seg { char name[17]; uint64_t vmaddr, vmsize; };

// LC_SEGMENT_64 extents of an image, read from its mach header inside the cache (small read, in memory only)
static int image_segments(const struct m3_cache *c, long idx, struct seg *out, int max)
{
    static uint8_t hdr[0x10000];
    const struct m3_image *im = &c->imgs[idx];
    const struct m3_mapping *m = m3_map_for(c, im->addr);
    if (!m) return -1;
    size_t n = sizeof hdr;
    if (im->addr + n > m->address + m->size) n = m->address + m->size - im->addr;
    if (m3_read_at(c, im->addr, hdr, n) || m3_rd32(hdr) != 0xfeedfacf) return -1;
    uint32_t ncmds = m3_rd32(hdr + 16), sz = m3_rd32(hdr + 20);
    if (32 + (uint64_t)sz > n) return -1;
    int ns = 0;
    const uint8_t *p = hdr + 32;
    for (uint32_t i = 0; i < ncmds; i++, p += m3_rd32(p + 4)) {
        if (m3_rd32(p) != 0x19 || ns >= max) continue;
        memcpy(out[ns].name, p + 8, 16);
        out[ns].name[16] = 0;
        out[ns].vmaddr = m3_rd64(p + 24);
        out[ns].vmsize = m3_rd64(p + 32);
        ns++;
    }
    return ns;
}


static int cmp_u64(const void *a, const void *b) { uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return x < y ? -1 : x > y; }
static long image_containing_text(const struct m3_cache *c, uint64_t a)
{
    for (uint32_t i = 0; i < c->nimgs; i++)
        if (a >= c->imgs[i].text_addr && a < c->imgs[i].text_addr + c->imgs[i].text_size) return (long)i;
    return -1;
}

struct nameent { uint64_t addr; const char *name; };
static int cmp_nameent(const void *a, const void *b) { const struct nameent *x = a, *y = b; return x->addr < y->addr ? -1 : x->addr > y->addr; }
struct gotent { uint64_t addr; uint32_t exporter, xi, flags; };
struct got_collect { struct gotent *g; size_t n, cap; };
static void got_cb(void *vctx, uint32_t exporter, uint32_t xi, int is_got, uint32_t client, uint64_t addr, uint32_t flags)
{
    struct got_collect *x = vctx;
    (void)client;
    if (!is_got) return;
    if (x->n == x->cap) { x->cap = x->cap ? x->cap * 2 : 1 << 16; x->g = realloc(x->g, x->cap * sizeof *x->g); if (!x->g) m3_die("realloc"); }
    x->g[x->n++] = (struct gotent){addr, exporter, xi, flags};
}
static int cmp_gotent(const void *a, const void *b) { const struct gotent *x = a, *y = b; return x->addr < y->addr ? -1 : x->addr > y->addr; }

struct symtab {
    struct nameent *names; size_t nnames;
    struct gotent *got; size_t ngot;
    const struct m3_cache *c; const struct pv4_view *v;
};
static struct symtab *symtab_build(const struct m3_cache *c, const struct pv4_view *v, const struct pv4_env *env)
{
    struct symtab *t = calloc(1, sizeof *t);
    t->c = c; t->v = v;
    t->names = malloc(v->h.imageExportsArrayCount * sizeof *t->names);
    for (uint32_t i = 0; i < v->h.patchTableArrayCount; i++)
        for (uint32_t e = 0; e < v->patches[i].exportsCount; e++) {
            uint32_t xi = v->patches[i].exportsStartIndex + e;
            t->names[t->nnames++] = (struct nameent){c->imgs[i].addr + v->exports[xi].dylibOffsetOfImpl, pv4_export_name(v, xi)};
        }
    qsort(t->names, t->nnames, sizeof *t->names, cmp_nameent);
    struct got_collect gc = {0};
    pv4_walk(v, env, got_cb, &gc);
    qsort(gc.g, gc.n, sizeof *gc.g, cmp_gotent);
    t->got = gc.g; t->ngot = gc.n;
    return t;
}
static const struct gotent *symtab_got(const struct symtab *t, uint64_t slot)
{
    struct gotent k = {.addr = slot};
    return bsearch(&k, t->got, t->ngot, sizeof *t->got, cmp_gotent);
}
static void print_target(const struct symtab *t, uint64_t a)
{
    struct nameent k = {.addr = a};
    const struct nameent *n = bsearch(&k, t->names, t->nnames, sizeof *t->names, cmp_nameent);
    long im = -1;
    for (uint32_t i = 0; i < t->c->nimgs; i++)
        if (a >= t->c->imgs[i].text_addr && a < t->c->imgs[i].text_addr + t->c->imgs[i].text_size) { im = (long)i; break; }
    if (n) printf("%s", n->name);
    else printf("(unnamed)");
    if (im >= 0) printf(" in %s +%#" PRIx64, t->c->imgs[im].path, a - t->c->imgs[im].text_addr); else printf(" at %#" PRIx64, a);
}

#endif
