// Modes that read the version-4 patch info and image headers: hdr, patchcheck, patchclient, patchsample,
// patchexporters/patchexports, slots, sections, stubs, imgexports. Included by m3_scan.c only.
#ifndef MODE_PATCH_H
#define MODE_PATCH_H
static int mode_hdr(struct m3_cache *c)
{
    uint32_t flags = m3_rd32(c->header + 0xdc);
    printf("platform %u\n", m3_rd32(c->header + 0xd8));
    printf("flags word %#x: formatVersion %u dylibsExpectedOnDisk %u simulator %u locallyBuiltCache %u builtFromChainedFixups %u newFormatTLVs %u (bits 13+: %#x)\n",
           flags, flags & 0xff, (flags >> 8) & 1, (flags >> 9) & 1, (flags >> 10) & 1, (flags >> 11) & 1, (flags >> 12) & 1, flags >> 13);
    printf("mappingOffset %#x mappingCount %u imagesCount %u (old %u)\n", m3_rd32(c->header + 0x10), m3_rd32(c->header + 0x14), m3_rd32(c->header + 0x1c4), m3_rd32(c->header + 0x1c));
    uint64_t pa = m3_rd64(c->header + 0x98), ps = m3_rd64(c->header + 0xa0);
    printf("patchInfo addr %#" PRIx64 " size %" PRIu64 "\n", pa, ps);
    const struct m3_mapping *m = m3_map_for(c, pa);
    if (m) printf("  inside mapping %#" PRIx64 "-%#" PRIx64 " file %d initProt %u; table ends %#" PRIx64 " (%s one mapping)\n", m->address, m->address + m->size, m->file, m->initProt, pa + ps,
                  pa + ps <= m->address + m->size ? "within" : "NOT within");
    for (int i = 0; i < c->nmaps; i++)
        printf("mapping %2d file %2d %#" PRIx64 "-%#" PRIx64 " fileOff %#" PRIx64 " initProt %u flags %#" PRIx64 " slideInfoSize %#" PRIx64 "\n", i, c->maps[i].file, c->maps[i].address, c->maps[i].address + c->maps[i].size, c->maps[i].fileOffset, c->maps[i].initProt, c->maps[i].flags, c->maps[i].slideInfoSize);
    uint8_t w[0x98];
    if (!m3_read_at(c, pa, w, sizeof w)) {
        printf("patch header words (hex):");
        for (int i = 0; i < 19; i++) printf(" %" PRIx64, m3_rd64(w + 8 * i));
        printf("\n");
    }
    return 0;
}


static int mode_patchcheck(struct m3_cache *c)
{
    uint64_t base, size;
    uint8_t *b = load_patch_blob(c, &base, &size);
    struct pv4_view v;
    char err[200];
    if (pv4_open(&v, b, base, size, err, sizeof err)) { printf("pv4_open failed: %s\n", err); return 1; }
    struct pv4_env env = make_env(c);
    static struct pv4_report rep;
    pv4_validate(&v, &env, &rep);
    printf("patch table v%u/%u: %" PRIu64 " exports, %" PRIu64 " locations, %" PRIu64 " got locations checked\n", v.h.patchTableVersion, v.h.patchLocationVersion, rep.exports_seen, rep.locations_seen, rep.got_locations_seen);
    uint64_t total = 0;
    for (int i = 0; i < PV4_E_COUNT; i++) {
        printf("  check %-20s violations %" PRIu64, pv4_check_name[i], rep.errors[i]);
        if (rep.errors[i]) printf(" (first at %#" PRIx64 ")", rep.first_bad[i]);
        printf("\n");
        total += rep.errors[i];
    }
    printf("total violations %" PRIu64 "\n", total);
    free(b);
    return total != 0;
}


struct hit { uint32_t exporter, export_index; int is_got; uint64_t addr; uint32_t flags; };
struct client_ctx {
    long client; const struct seg *segs; int nsegs;
    struct hit *hits; size_t n, cap;
    uint64_t plain_by_index, plain_by_index_outside, got_inside;
};
static void client_cb(void *vctx, uint32_t exporter, uint32_t xi, int is_got, uint32_t client, uint64_t addr, uint32_t flags)
{
    struct client_ctx *x = vctx;
    int inside = 0;
    for (int i = 0; i < x->nsegs; i++) if (addr >= x->segs[i].vmaddr && addr < x->segs[i].vmaddr + x->segs[i].vmsize) inside = 1;
    if (!is_got) {
        if (client != (uint32_t)x->client) return;
        x->plain_by_index++;
        if (!inside) x->plain_by_index_outside++;
    } else {
        if (!inside) return;
        x->got_inside++;
    }
    if (x->n == x->cap) { x->cap = x->cap ? x->cap * 2 : 1024; x->hits = realloc(x->hits, x->cap * sizeof *x->hits); if (!x->hits) m3_die("realloc"); }
    x->hits[x->n++] = (struct hit){exporter, xi, is_got, addr, flags};
}
static int cmp_hit(const void *a, const void *b)
{
    const struct hit *x = a, *y = b;
    if (x->exporter != y->exporter) return x->exporter < y->exporter ? -1 : 1;
    if (x->export_index != y->export_index) return x->export_index < y->export_index ? -1 : 1;
    return x->addr < y->addr ? -1 : x->addr > y->addr;
}

// patchclient <install name> [list] : exporters/symbols whose patch locations lie in this image's segments
static int mode_patchclient(struct m3_cache *c, const char *client_path, int list, int nsamples)
{
    long ci = m3_find_image(c, client_path);
    if (ci < 0) { printf("no such image %s\n", client_path); return 1; }
    struct seg segs[16];
    int ns = image_segments(c, ci, segs, 16);
    if (ns < 0) m3_die("image segments");
    uint64_t base, size;
    uint8_t *b = load_patch_blob(c, &base, &size);
    struct pv4_view v;
    char err[200];
    if (pv4_open(&v, b, base, size, err, sizeof err)) { printf("pv4_open failed: %s\n", err); return 1; }
    struct pv4_env env = make_env(c);
    struct client_ctx x = {.client = ci, .segs = segs, .nsegs = ns};
    pv4_walk(&v, &env, client_cb, &x);
    printf("client %s image %ld at %#" PRIx64 "\n", client_path, ci, c->imgs[ci].addr);
    for (int i = 0; i < ns; i++) printf("  segment %-16s %#" PRIx64 " size %#" PRIx64 "\n", segs[i].name, segs[i].vmaddr, segs[i].vmsize);
    printf("  plain locations by client index %" PRIu64 " (outside the image's segments: %" PRIu64 "), got locations inside the segments %" PRIu64 "\n", x.plain_by_index, x.plain_by_index_outside, x.got_inside);
    qsort(x.hits, x.n, sizeof *x.hits, cmp_hit);
    uint64_t pairs = 0;
    for (size_t i = 0; i < x.n;) {
        size_t j = i;
        uint64_t np = 0, ng = 0;
        while (j < x.n && x.hits[j].exporter == x.hits[i].exporter && x.hits[j].export_index == x.hits[i].export_index) { if (x.hits[j].is_got) ng++; else np++; j++; }
        printf("R\t%s\t%s\t%s\t%" PRIu64 "\t%" PRIu64 "\n", client_path, c->imgs[x.hits[i].exporter].path, pv4_export_name(&v, x.hits[i].export_index), np, ng);
        pairs++;
        i = j;
    }
    printf("  distinct (exporter, symbol) pairs %" PRIu64 "\n", pairs);
    if (list)
        for (size_t i = 0; i < x.n; i++)
            printf("L\t%s\t%" PRIx64 "\t%d\t%08x\t%s\n", client_path, x.hits[i].addr - c->imgs[ci].addr, x.hits[i].is_got, x.hits[i].flags, pv4_export_name(&v, x.hits[i].export_index));
    // sample the chain-encoded slot words for locations (evenly spaced) to decode the flag bits
    for (int k = 0; k < nsamples && x.n; k++) {
        const struct hit *h = &x.hits[(size_t)k * x.n / (size_t)nsamples];
        uint64_t raw;
        if (m3_read_at(c, h->addr, &raw, 8)) { printf("  sample unreadable\n"); continue; }
        printf("S\tflags %08x got %d slot auth %u key %u addrDiv %u div %04x next %u\n", h->flags, h->is_got, (unsigned)(raw >> 63), (unsigned)((raw >> 51) & 1), (unsigned)((raw >> 50) & 1), (unsigned)((raw >> 34) & 0xffff), (unsigned)((raw >> 52) & 0x7ff));
    }
    free(x.hits);
    free(b);
    return 0;
}

struct samp_ctx { struct hit *h; size_t n, cap, step, seen[2]; uint32_t only_mask; };
static void samp_cb(void *vctx, uint32_t exporter, uint32_t xi, int is_got, uint32_t client, uint64_t addr, uint32_t flags)
{
    struct samp_ctx *x = vctx;
    (void)client;
    if ((flags & x->only_mask) ? 0 : (x->seen[is_got]++ % x->step)) return;
    if (x->n == x->cap) { x->cap = x->cap ? x->cap * 2 : 4096; x->h = realloc(x->h, x->cap * sizeof *x->h); if (!x->h) m3_die("realloc"); }
    x->h[x->n++] = (struct hit){exporter, xi, is_got, addr, flags};
}
static int cmp_hit_addr(const void *a, const void *b)
{
    const struct hit *x = a, *y = b;
    return x->addr < y->addr ? -1 : x->addr > y->addr;
}

// patchsample <every-nth>: read the slot words of every nth location (ascending addresses) and compare with the table
static int mode_patchsample(struct m3_cache *c, size_t step, uint32_t only_mask)
{
    uint64_t base, size;
    uint8_t *b = load_patch_blob(c, &base, &size);
    struct pv4_view v;
    char err[200];
    if (pv4_open(&v, b, base, size, err, sizeof err)) { printf("pv4_open failed: %s\n", err); return 1; }
    struct pv4_env env = make_env(c);
    struct samp_ctx x = {.step = step, .only_mask = only_mask};
    pv4_walk(&v, &env, samp_cb, &x);
    qsort(x.h, x.n, sizeof *x.h, cmp_hit_addr);
    uint64_t match[2] = {0}, mismatch[2] = {0}, unread = 0, dec_ok = 0, dec_bad = 0, bit8[2] = {0};
    static uint64_t by_kind_total[16], by_kind_match[16];
    unsigned shown = 0;
    for (size_t i = 0; i < x.n; i++) {
        const struct hit *h = &x.h[i];
        uint64_t raw;
        if (m3_read_at(c, h->addr, &raw, 8)) { unread++; continue; }
        unsigned auth = (unsigned)(raw >> 63);
        uint64_t target = c->maps[0].address + (raw & 0x3ffffffffULL);
        uint32_t nk = v.exports[h->export_index].nameKind;
        uint64_t impl = c->imgs[h->exporter].addr + v.exports[h->export_index].dylibOffsetOfImpl;
        struct pv4_fixup d = pv4_decode_flags(h->flags);
        by_kind_total[PV4_NAME_KIND(nk)]++;
        int ok = target == impl + d.addend;
        if (ok) { match[h->is_got]++; by_kind_match[PV4_NAME_KIND(nk)]++; } else mismatch[h->is_got]++;
        bit8[h->is_got] += d.bit8;
        int fix_ok = d.authenticated == auth;
        if (fix_ok && auth) fix_ok = d.key == ((raw >> 51) & 1) && d.usesAddressDiversity == ((raw >> 50) & 1) && d.discriminator == ((raw >> 34) & 0xffff);
        if (fix_ok && !auth) fix_ok = d.high7 << 1 == ((raw >> 34) & 0xff);
        if (fix_ok && ok) dec_ok++; else { dec_bad++; if (shown++ < 8) printf("  MISMATCH flags %08x got %d slot auth %u key %u addrDiv %u div %04x high8 %02x target-impl %" PRId64 " in %s::%s\n", h->flags, h->is_got, auth, (unsigned)((raw >> 51) & 1), (unsigned)((raw >> 50) & 1), (unsigned)((raw >> 34) & 0xffff), (unsigned)((raw >> 34) & 0xff), (int64_t)(target - impl), c->imgs[h->exporter].path, pv4_export_name(&v, h->export_index)); }
    }
    printf("sampled %zu locations (every %zu%s): unreadable %" PRIu64 "\n", x.n, step, only_mask ? " plus all with the mask" : "", unread);
    for (int g = 0; g < 2; g++)
        printf("  %s: slot target == exporter+impl+addend %" PRIu64 ", differs %" PRIu64 "; flags bit 8 set %" PRIu64 "\n", g ? "got" : "plain", match[g], mismatch[g], bit8[g]);
    for (int k = 0; k < 16; k++) if (by_kind_total[k]) printf("  export kind %d: %" PRIu64 " sampled, target matches %" PRIu64 "\n", k, by_kind_total[k], by_kind_match[k]);
    printf("  decode_flags agrees with slot (auth, key, addrDiv, discriminator or high8, addend): %" PRIu64 " of %" PRIu64 "\n", dec_ok, dec_ok + dec_bad);
    free(x.h);
    free(b);
    return 0;
}

struct exp_ctx { uint64_t *plain, *got; };
static void exp_cb(void *vctx, uint32_t exporter, uint32_t xi, int is_got, uint32_t client, uint64_t addr, uint32_t flags)
{
    struct exp_ctx *x = vctx;
    (void)xi; (void)client; (void)addr; (void)flags;
    (is_got ? x->got : x->plain)[exporter]++;
}

// patchexporters <path>...: per exporting image, patchable exports, client images and patch locations by table
static int mode_patchexporters(struct m3_cache *c, int n, char **paths, int list_exports)
{
    uint64_t base, size;
    uint8_t *b = load_patch_blob(c, &base, &size);
    struct pv4_view v;
    char err[200];
    if (pv4_open(&v, b, base, size, err, sizeof err)) { printf("pv4_open failed: %s\n", err); return 1; }
    struct pv4_env env = make_env(c);
    struct exp_ctx x = {calloc(c->nimgs, 8), calloc(c->nimgs, 8)};
    pv4_walk(&v, &env, exp_cb, &x);
    for (int k = 0; k < n; k++) {
        long i = m3_find_image(c, paths[k]);
        if (i < 0) { printf("X\t%s\tnot in cache\n", paths[k]); continue; }
        const struct pv4_image_patches *p = &v.patches[i];
        uint64_t gexp = i < (long)v.h.gotClientsArrayCount ? v.gotClients[i].exportsCount : 0;
        printf("E\t%s\timage %ld\texports %u\tclients %u\tplain_locations %" PRIu64 "\tgot_exports %" PRIu64 "\tgot_locations %" PRIu64 "\n", paths[k], i, p->exportsCount, p->clientsCount, x.plain[i], gexp, x.got[i]);
        if (list_exports) {
            // per export: plain and got location counts
            for (uint32_t e = 0; e < p->exportsCount; e++) {
                uint32_t xi = p->exportsStartIndex + e;
                uint64_t np = 0, ng = 0;
                for (uint64_t j = p->clientsStartIndex; j < (uint64_t)p->clientsStartIndex + p->clientsCount; j++)
                    for (uint64_t q = v.clients[j].exportsStartIndex; q < (uint64_t)v.clients[j].exportsStartIndex + v.clients[j].exportsCount; q++)
                        if (v.clientExports[q].imageExportIndex == xi) np += v.clientExports[q].locationsCount;
                if (i < (long)v.h.gotClientsArrayCount)
                    for (uint64_t q = v.gotClients[i].exportsStartIndex; q < (uint64_t)v.gotClients[i].exportsStartIndex + v.gotClients[i].exportsCount; q++)
                        if (v.gotClientExports[q].imageExportIndex == xi) ng += v.gotClientExports[q].locationsCount;
                printf("N\t%s\t%s\t%u\t%" PRIu64 "\t%" PRIu64 "\n", paths[k], pv4_export_name(&v, xi), PV4_NAME_KIND(v.exports[xi].nameKind), np, ng);
            }
        }
    }
    free(x.plain); free(x.got); free(b);
    return 0;
}


// slots <path>: for every pointer-sized slot of the image's __AUTH_CONST/__DATA_CONST/__DATA/__AUTH segments print which
// image its target lies in (install name) and whether the patch table lists the slot's address
struct slot_ctx { uint64_t *addrs; size_t n, cap; };
static void slot_cb(void *vctx, uint32_t exporter, uint32_t xi, int is_got, uint32_t client, uint64_t addr, uint32_t flags)
{
    struct slot_ctx *x = vctx;
    (void)exporter; (void)xi; (void)is_got; (void)client; (void)flags;
    if (x->n == x->cap) { x->cap = x->cap ? x->cap * 2 : 1 << 20; x->addrs = realloc(x->addrs, x->cap * 8); if (!x->addrs) m3_die("realloc"); }
    x->addrs[x->n++] = addr;
}
static int mode_slots(struct m3_cache *c, const char *path)
{
    long ci = m3_find_image(c, path);
    if (ci < 0) return 1;
    struct seg segs[16];
    int ns = image_segments(c, ci, segs, 16);
    uint64_t base, size;
    uint8_t *b = load_patch_blob(c, &base, &size);
    struct pv4_view v;
    char err[200];
    if (pv4_open(&v, b, base, size, err, sizeof err)) return 1;
    struct pv4_env env = make_env(c);
    struct slot_ctx sc = {0};
    pv4_walk(&v, &env, slot_cb, &sc);
    qsort(sc.addrs, sc.n, 8, cmp_u64);
    for (int s = 0; s < ns; s++) {
        if (!strcmp(segs[s].name, "__TEXT") || !strcmp(segs[s].name, "__LINKEDIT")) continue;
        uint64_t listed = 0, slots = 0, auth = 0;
        for (uint64_t a = segs[s].vmaddr; a + 8 <= segs[s].vmaddr + segs[s].vmsize; a += 8) {
            uint64_t raw;
            if (m3_read_at(c, a, &raw, 8)) continue;
            int is_listed = bsearch(&a, sc.addrs, sc.n, 8, cmp_u64) != NULL;
            if (getenv("M3_RAW") && a - segs[s].vmaddr < 0x90) printf("raw +%" PRIx64 " %016" PRIx64 "\n", a - segs[s].vmaddr, raw);
            if (!raw) continue; // empty slot
            slots++;
            listed += is_listed;
            auth += raw >> 63;
            uint64_t t = c->maps[0].address + (raw & 0x3ffffffffULL);
            long ti = image_containing_text(c, t);
            printf("T\t%s\t%s\t+%" PRIx64 "\tauth %u\tlisted %d\t-> %s +%" PRIx64 "\n", path, segs[s].name, a - segs[s].vmaddr, (unsigned)(raw >> 63), is_listed, ti >= 0 ? c->imgs[ti].path : "(data/other)", ti >= 0 ? t - c->imgs[ti].text_addr : t);
        }
        printf("  segment %s: %" PRIu64 " non-empty 8-byte words, %" PRIu64 " authenticated, %" PRIu64 " listed in the patch table\n", segs[s].name, slots, auth, listed);
    }
    free(sc.addrs); free(b);
    return 0;
}


// sections <path>: segment/section table of an image (names, addresses, sizes, flags) and its dylib/chained-fixup load commands
static int mode_sections(struct m3_cache *c, const char *path)
{
    long ci = m3_find_image(c, path);
    if (ci < 0) return 1;
    static uint8_t hdr[0x10000];
    if (m3_read_at(c, c->imgs[ci].addr, hdr, sizeof hdr)) m3_die("header read");
    uint32_t ncmds = m3_rd32(hdr + 16);
    const uint8_t *p = hdr + 32;
    for (uint32_t i = 0; i < ncmds; i++, p += m3_rd32(p + 4)) {
        uint32_t cmd = m3_rd32(p);
        if (cmd == 0x19) {
            uint32_t nsects = m3_rd32(p + 64);
            printf("seg %-16s vmaddr %#" PRIx64 " vmsize %#" PRIx64 " prot %u/%u nsects %u\n", (const char *)(p + 8), m3_rd64(p + 24), m3_rd64(p + 32), m3_rd32(p + 60), m3_rd32(p + 56), nsects);
            for (uint32_t k = 0; k < nsects; k++) {
                const uint8_t *s = p + 72 + (size_t)k * 80;
                printf("  sect %-16s addr %#" PRIx64 " size %#" PRIx64 " flags %#x r1 %u r2 %u\n", (const char *)s, m3_rd64(s + 32), m3_rd64(s + 40), m3_rd32(s + 64), m3_rd32(s + 68), m3_rd32(s + 72));
            }
        } else if (cmd == 0xc || cmd == 0x8000001f || cmd == 0x80000018 || cmd == 0x80000023)
            printf("dylib cmd %#x %s\n", cmd, (const char *)(p + m3_rd32(p + 8)));
        else if (cmd == 0x80000034 || cmd == 0x80000033 || cmd == 0x22 || cmd == 0x80000022 || cmd == 0x2 || cmd == 0xb)
            printf("cmd %#x size %u\n", cmd, m3_rd32(p + 4));
    }
    return 0;
}

// stubs <path> <section addr> <size>: decode adrp/add/ldr/braa stubs, print the GOT slot address (image offset) and raw slot word
static int mode_stubs(struct m3_cache *c, const char *path, uint64_t saddr, uint64_t ssize)
{
    long ci = m3_find_image(c, path);
    if (ci < 0) return 1;
    for (uint64_t pc = saddr; pc + 16 <= saddr + ssize; pc += 16) {
        uint32_t w[4];
        if (m3_read_at(c, pc, w, 16)) return 1;
        int shape = (w[0] & 0x9F00001Fu) == 0x90000011u && (w[1] & 0xFFC003FFu) == 0x91000231u && w[2] == 0xF9400230u && w[3] == 0xD71F0A11u;
        int64_t imm = (int64_t)(((w[0] >> 29) & 3) | (((w[0] >> 5) & 0x7FFFF) << 2));
        imm = (imm << 43) >> 43;
        uint64_t slot = (pc & ~0xFFFULL) + (uint64_t)(imm << 12) + ((w[1] >> 10) & 0xFFF);
        uint64_t raw = 0;
        m3_read_at(c, slot, &raw, 8);
        printf("stub +%" PRIx64 " shape %d slot image+%" PRIx64 " raw %016" PRIx64 "\n", pc - c->imgs[ci].addr, shape, slot - c->imgs[ci].addr, raw);
    }
    return 0;
}


// imgexports <path>: export trie of a cache image (LC_DYLD_EXPORTS_TRIE inside the shared __LINKEDIT) and its re-exports
static void imgexp_cb(void *ctx, const char *name, uint64_t flags, uint64_t value, const char *imp)
{
    (void)ctx;
    printf("E\t%s\t%#" PRIx64 "\t%#" PRIx64 "\t%s\n", name, flags, value, imp ? (*imp ? imp : "-") : "-");
}
static int mode_imgexports(struct m3_cache *c, const char *path)
{
    long ci = m3_find_image(c, path);
    if (ci < 0) return 1;
    static uint8_t hdr[0x10000];
    if (m3_read_at(c, c->imgs[ci].addr, hdr, sizeof hdr)) m3_die("header read");
    uint32_t ncmds = m3_rd32(hdr + 16);
    const uint8_t *p = hdr + 32;
    uint64_t le_vm = 0, le_fo = 0;
    uint32_t eoff = 0, esize = 0;
    for (uint32_t i = 0; i < ncmds; i++, p += m3_rd32(p + 4)) {
        uint32_t cmd = m3_rd32(p);
        if (cmd == 0x19 && !strcmp((const char *)(p + 8), "__LINKEDIT")) { le_vm = m3_rd64(p + 24); le_fo = m3_rd64(p + 40); }
        else if (cmd == 0x80000033) { eoff = m3_rd32(p + 8); esize = m3_rd32(p + 12); }
        else if (cmd == 0x8000001f || cmd == 0x80000018) printf("R\t%s\n", (const char *)(p + m3_rd32(p + 8)));
    }
    if (!esize) { printf("no export trie\n"); return 0; }
    uint8_t *t = malloc(esize);
    if (!t || m3_read_at(c, le_vm + (eoff - le_fo), t, esize)) m3_die("trie read");
    long n = trie_walk(t, esize, imgexp_cb, NULL);
    printf("exports %ld (trie %u bytes)\n", n, esize);
    free(t);
    return 0;
}

#endif
