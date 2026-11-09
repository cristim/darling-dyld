// initwalk and imports modes: calls and constant structs of an image initializer, and the (exporter, symbol) pairs
// an image reaches through stub/GOT slots. Included by m3_scan.c only.
#ifndef MODE_INIT_H
#define MODE_INIT_H
// ---- initwalk: calls made by an image's initializer (names via stubs, GOT slots and the patch table) and the
// ---- constant structs it passes; prints interface facts only (names, offsets, version words, word counts)
enum { RK_UNK, RK_IMM, RK_ADDR, RK_SP };
struct rv { int k; uint64_t v; };

static int mode_initwalk(struct m3_cache *c, const char *path, long max_calls)
{
    long ci = m3_find_image(c, path);
    if (ci < 0) return 1;
    static uint8_t hdr[0x10000];
    if (m3_read_at(c, c->imgs[ci].addr, hdr, sizeof hdr)) m3_die("header read");
    struct { char name[17]; uint64_t addr, size; uint32_t flags; } secs[32];
    int nsec = 0;
    uint32_t ncmds = m3_rd32(hdr + 16);
    const uint8_t *p = hdr + 32;
    for (uint32_t i = 0; i < ncmds; i++, p += m3_rd32(p + 4))
        if (m3_rd32(p) == 0x19)
            for (uint32_t k = 0; k < m3_rd32(p + 64) && nsec < 32; k++) {
                const uint8_t *s = p + 72 + (size_t)k * 80;
                memcpy(secs[nsec].name, s, 16); secs[nsec].name[16] = 0;
                secs[nsec].addr = m3_rd64(s + 32); secs[nsec].size = m3_rd64(s + 40); secs[nsec].flags = m3_rd32(s + 64);
                nsec++;
            }
    uint64_t base, size;
    uint8_t *b = load_patch_blob(c, &base, &size);
    struct pv4_view v;
    char err[200];
    if (pv4_open(&v, b, base, size, err, sizeof err)) return 1;
    struct pv4_env env = make_env(c);
    struct symtab *t = symtab_build(c, &v, &env);
    uint64_t text = c->imgs[ci].text_addr;
    uint64_t stubs_lo = 0, stubs_hi = 0, code_lo = 0, code_hi = 0, init_addr = 0;
    for (int i = 0; i < nsec; i++) {
        if (!strcmp(secs[i].name, "__auth_stubs") || !strcmp(secs[i].name, "__stubs")) { stubs_lo = secs[i].addr; stubs_hi = secs[i].addr + secs[i].size; }
        if (!strcmp(secs[i].name, "__text")) { code_lo = secs[i].addr; code_hi = secs[i].addr + secs[i].size; }
        if ((secs[i].flags & 0xff) == 0x16) { // S_INIT_FUNC_OFFSETS: 32-bit offsets from the image start
            for (uint64_t o = 0; o + 4 <= secs[i].size; o += 4) {
                uint32_t f;
                m3_read_at(c, secs[i].addr + o, &f, 4);
                printf("init_offsets[%" PRIu64 "] = +%#x\n", o / 4, f);
                if (!init_addr) init_addr = text + f;
            }
        }
    }
    if (!init_addr) { printf("no __init_offsets\n"); return 1; }
    uint32_t w[0x2000];
    uint64_t nwords = code_hi - init_addr < sizeof w ? (code_hi - init_addr) / 4 : sizeof w / 4;
    if (m3_read_at(c, init_addr, w, nwords * 4)) m3_die("code read");
    struct rv r[32] = {{0}};
    struct { uint64_t sp_off; int size; int known; uint64_t val; uint64_t pc; } stores[256];
    unsigned nst = 0;
    long ncalls = 0;
    uint64_t struct_addrs[32];
    unsigned nstruct = 0;
    printf("initializer at +%#" PRIx64 " (%" PRIu64 " words scanned to the end of __text)\n", init_addr - text, nwords);
    for (uint64_t k = 0; k < nwords && ncalls < max_calls; k++) {
        uint32_t x = w[k];
        uint64_t pc = init_addr + k * 4;
        unsigned rd = x & 31, rn = (x >> 5) & 31;
        if ((x & 0x9F000000u) == 0x90000000u) { // adrp
            int64_t imm = (int64_t)(((x >> 29) & 3) | (((x >> 5) & 0x7FFFF) << 2));
            imm = (imm << 43) >> 43;
            r[rd] = (struct rv){RK_ADDR, (pc & ~0xFFFULL) + (uint64_t)(imm << 12)};
        } else if ((x & 0xFF800000u) == 0x91000000u) { // add Xd, Xn|SP, #imm
            uint64_t imm = ((x >> 10) & 0xFFF) << (((x >> 22) & 1) ? 12 : 0);
            struct rv src = rn == 31 ? (struct rv){RK_SP, 0} : r[rn];
            if (src.k != RK_UNK && rd != 31) r[rd] = (struct rv){src.k, src.v + imm}; else if (rd != 31) r[rd] = (struct rv){RK_UNK, 0};
        } else if ((x & 0x1F800000u) == 0x12800000u && ((x >> 29) & 3) != 1) { // mov wide
            unsigned opc = (x >> 29) & 3, sh = ((x >> 21) & 3) * 16;
            uint64_t imm = (x >> 5) & 0xFFFF, mask = (x >> 31) ? ~0ULL : 0xFFFFFFFFULL;
            if (rd != 31) {
                if (opc == 2) r[rd] = (struct rv){RK_IMM, (imm << sh) & mask};
                else if (opc == 0) r[rd] = (struct rv){RK_IMM, ~(imm << sh) & mask};
                else if (r[rd].k == RK_IMM) r[rd].v = ((r[rd].v & ~(0xFFFFULL << sh)) | (imm << sh)) & mask;
                else r[rd] = (struct rv){RK_UNK, 0};
            }
        } else if ((x & 0xFFE0FFE0u) == 0xAA0003E0u) { // mov Xd, Xm
            if (rd != 31) r[rd] = r[(x >> 16) & 31];
        } else if ((x & 0xFFE0FFE0u) == 0x2A0003E0u) { // mov Wd, Wm
            if (rd != 31) { r[rd] = r[(x >> 16) & 31]; if (r[rd].k == RK_IMM) r[rd].v &= 0xFFFFFFFFULL; }
        } else if ((x & 0xFC000000u) == 0x94000000u) { // bl
            int64_t off = ((int64_t)(int32_t)((x & 0x03FFFFFFu) << 6) >> 6) * 4;
            uint64_t tgt = pc + (uint64_t)off;
            printf("call %ld at +%#" PRIx64 " -> ", ncalls++, pc - text);
            if (tgt >= stubs_lo && tgt < stubs_hi) {
                uint32_t sw[4];
                m3_read_at(c, tgt, sw, 16);
                int64_t im2 = (int64_t)(((sw[0] >> 29) & 3) | (((sw[0] >> 5) & 0x7FFFF) << 2));
                im2 = (im2 << 43) >> 43;
                uint64_t slot = (tgt & ~0xFFFULL) + (uint64_t)(im2 << 12) + ((sw[1] >> 10) & 0xFFF);
                const struct gotent *g = symtab_got(t, slot);
                uint64_t sraw = 0;
                m3_read_at(c, slot, &sraw, 8);
                printf("stub +%#" PRIx64 " slot +%#" PRIx64 " = ", tgt - text, slot - text);
                if (g) printf("patch-table GOT slot of %s::%s", c->imgs[g->exporter].path, pv4_export_name(&v, g->xi));
                else if (sraw) { printf("slot holds "); print_target(t, c->maps[0].address + (sraw & 0x3ffffffffULL)); }
                else printf("empty slot, not in the patch table");
            } else if (tgt >= code_lo && tgt < code_hi) printf("local function +%#" PRIx64, tgt - text);
            else printf("other %#" PRIx64, tgt);
            printf("\n");
            for (int a = 0; a < 4; a++) {
                if (r[a].k == RK_IMM) printf("  x%d = imm %#" PRIx64 "\n", a, r[a].v);
                else if (r[a].k == RK_SP) printf("  x%d = sp+%#" PRIx64 "\n", a, r[a].v);
                else if (r[a].k == RK_ADDR) {
                    const char *sn = "?";
                    for (int i = 0; i < nsec; i++) if (r[a].v >= secs[i].addr && r[a].v < secs[i].addr + secs[i].size) sn = secs[i].name;
                    printf("  x%d = image+%#" PRIx64 " (%s)\n", a, r[a].v - text, sn);
                    if (a == 0 && nstruct < 32 && (strstr(sn, "const") && strcmp(sn, "__cstring"))) { int dup = 0; for (unsigned q = 0; q < nstruct; q++) dup |= struct_addrs[q] == r[a].v; if (!dup) struct_addrs[nstruct++] = r[a].v; }
                }
            }
            if (nst) {
                printf("  stack stores since the previous call:");
                for (unsigned q = 0; q < nst; q++) { uint64_t so = stores[q].sp_off; const char *rel = ""; (void)rel; if (stores[q].known) printf(" [sp+%#" PRIx64 "]:%d=%#" PRIx64, so, stores[q].size, stores[q].val); else printf(" [sp+%#" PRIx64 "]:%d=?", so, stores[q].size); }
                printf("\n");
                nst = 0;
            }
            for (int a = 0; a < 19; a++) r[a] = (struct rv){RK_UNK, 0};
        } else if ((x & 0xFFFFFC1Fu) == 0xD63F0000u || (x & 0xFFFFFC1Fu) == 0xD73F0800u || (x & 0xFFFFFC00u) == 0xD63F0800u) { // blr / blraa*
            printf("call %ld at +%#" PRIx64 " -> indirect (x%u)\n", ncalls++, pc - text, rn);
            for (int a = 0; a < 19; a++) r[a] = (struct rv){RK_UNK, 0};
        } else if ((x & 0x3FC00000u) == 0x39000000u || (x & 0x3FE00C00u) == 0x38000000u) { // str/strb/strh/stur unsigned or unscaled
            unsigned sz = x >> 30;
            int64_t imm = (x & 0x3FC00000u) == 0x39000000u ? (int64_t)((x >> 10) & 0xFFF) << sz : ((int64_t)(int32_t)(x << 11)) >> 23;
            if ((x >> 26 & 1) == 0 && ((x >> 22) & 3) == 0 && (rn == 31 || r[rn].k == RK_SP) && nst < 256) {
                struct rv val = rd == 31 ? (struct rv){RK_IMM, 0} : r[rd];
                stores[nst++] = (typeof(stores[0])){(uint64_t)imm + (rn == 31 ? 0 : r[rn].v), 1 << sz, val.k == RK_IMM, val.v, pc};
            } else if (rd != 31 && ((x >> 22) & 3) != 0) r[rd] = (struct rv){RK_UNK, 0};
        } else if ((x & 0x3FC00000u) == 0x29000000u || (x & 0x3FC00000u) == 0x2D000000u) { // stp offset (rare in the init path)
            if (nst + 2 <= 256 && (rn == 31 || r[rn].k == RK_SP) && !(x >> 26 & 1)) {
                unsigned scale = 2 + ((x >> 30) >> 1);
                int64_t imm = ((int64_t)(int32_t)(x << 10) >> 25) * (int64_t)(1u << scale);
                unsigned rt2 = (x >> 10) & 31;
                struct rv a = rd == 31 ? (struct rv){RK_IMM, 0} : r[rd], bb = rt2 == 31 ? (struct rv){RK_IMM, 0} : r[rt2];
                uint64_t off = (uint64_t)imm + (rn == 31 ? 0 : r[rn].v);
                stores[nst++] = (typeof(stores[0])){off, 1 << scale, a.k == RK_IMM, a.v, pc};
                stores[nst++] = (typeof(stores[0])){off + (1u << scale), 1 << scale, bb.k == RK_IMM, bb.v, pc};
            }
        } else if (x == 0xD65F03C0u || (x & 0xFFFFFBFFu) == 0xD65F0BFFu) { // ret / retaa / retab
            printf("ret at +%#" PRIx64 " (end of the initializer)\n", pc - text);
            break;
        } else {
            // any other write to a general register invalidates it
            uint32_t cls = (x >> 25) & 0xF;
            if (cls == 8 || cls == 9 || cls == 5 || cls == 13) r[rd] = (struct rv){RK_UNK, 0};
            else if ((cls & 5) == 4 && ((x >> 22) & 1) && !((x >> 26) & 1)) r[rd] = (struct rv){RK_UNK, 0};
        }
    }
    // constant structs passed in x0: words between consecutive struct start addresses
    qsort(struct_addrs, nstruct, 8, cmp_u64);
    for (unsigned q = 0; q < nstruct; q++) {
        uint64_t a0 = struct_addrs[q];
        uint64_t limit = q + 1 < nstruct ? struct_addrs[q + 1] : a0 + 0x80;
        const char *sn = "?";
        uint64_t send = a0;
        for (int i = 0; i < nsec; i++) if (a0 >= secs[i].addr && a0 < secs[i].addr + secs[i].size) { sn = secs[i].name; send = secs[i].addr + secs[i].size; }
        if (limit > send) limit = send;
        printf("struct passed as first argument at image+%#" PRIx64 " (%s), %" PRIu64 " bytes to the next struct or section end:\n", a0 - text, sn, limit - a0);
        for (uint64_t a = a0; a + 8 <= limit; a += 8) {
            uint64_t raw;
            m3_read_at(c, a, &raw, 8);
            if (raw >> 63) {
                uint64_t tg = c->maps[0].address + (raw & 0x3ffffffffULL);
                printf("  +%#" PRIx64 ": auth ptr key %s div %#" PRIx64 " addrDiv %u -> ", a - a0, ((raw >> 51) & 1) ? "DA" : "IA", (raw >> 34) & 0xffff, (unsigned)((raw >> 50) & 1));
                print_target(t, tg);
                printf("\n");
            } else if ((raw & 0x3ffffffffULL) >= 0x100000 && ((raw >> 34) & 0xff) == 0 && (raw & 0x3ffffffffULL) < 0x166464000ULL && ((raw >> 52) & 0x7ff) < 0x400 && raw != 0 && (raw >> 41) == 0)
                { printf("  +%#" PRIx64 ": plain ptr -> ", a - a0); print_target(t, c->maps[0].address + (raw & 0x3ffffffffULL)); printf("\n"); }
            else printf("  +%#" PRIx64 ": word %#" PRIx64 "\n", a - a0, raw);
        }
    }
    free(b);
    return 0;
}

// ---- imports <path>...: (exporting image, symbol) pairs the image reaches through stub/GOT slot loads in its code
struct imp_ctx { uint64_t *slots; uint64_t *sites; size_t n, cap; };
static void imp_slotref(void *vctx, uint64_t pc, uint64_t slot)
{
    struct imp_ctx *x = vctx;
    (void)pc;
    for (size_t i = 0; i < x->n; i++) if (x->slots[i] == slot) { x->sites[i]++; return; }
    if (x->n == x->cap) { x->cap = x->cap ? x->cap * 2 : 256; x->slots = realloc(x->slots, x->cap * 8); x->sites = realloc(x->sites, x->cap * 8); if (!x->slots || !x->sites) m3_die("realloc"); }
    x->slots[x->n] = slot; x->sites[x->n++] = 1;
}
struct pair { const char *exporter, *name; uint64_t sites; uint32_t flags; int has_flags; };
static int cmp_pair(const void *a, const void *b)
{
    const struct pair *x = a, *y = b;
    int d = strcmp(x->exporter, y->exporter);
    return d ? d : strcmp(x->name, y->name);
}
static int mode_imports(struct m3_cache *c, int n, char **paths)
{
    uint64_t base, size;
    uint8_t *b = load_patch_blob(c, &base, &size);
    struct pv4_view v;
    char err[200];
    if (pv4_open(&v, b, base, size, err, sizeof err)) return 1;
    struct pv4_env env = make_env(c);
    struct symtab *t = symtab_build(c, &v, &env);
    static uint8_t buf[4u << 20];
    for (int k = 0; k < n; k++) {
        long ci = m3_find_image(c, paths[k]);
        if (ci < 0) { printf("X\t%s\tnot in cache\n", paths[k]); continue; }
        struct m3_image *im = &c->imgs[ci];
        struct imp_ctx x = {0};
        struct a64_state st;
        a64_init(&st);
        st.slotref = imp_slotref;
        st.slotref_ctx = &x;
        for (int s = 0; s < im->nsec; s++) {
            for (uint64_t off = 0; off < im->secs[s].size; off += sizeof buf) {
                size_t len = im->secs[s].size - off < sizeof buf ? (size_t)(im->secs[s].size - off) : sizeof buf;
                len &= ~(size_t)3;
                if (!len) break;
                if (m3_read_at(c, im->secs[s].addr + off, buf, len)) m3_die("text read");
                a64_feed(&st, (const uint32_t *)buf, len / 4, im->secs[s].addr + off);
            }
            memset(st.pg, 0, sizeof st.pg);
        }
        struct pair *pairs = calloc(x.n ? x.n : 1, sizeof *pairs);
        size_t np = 0, unresolved = 0, own = 0;
        for (size_t i = 0; i < x.n; i++) {
            const struct gotent *g = symtab_got(t, x.slots[i]);
            if (g) { pairs[np++] = (struct pair){c->imgs[g->exporter].path, pv4_export_name(&v, g->xi), x.sites[i], g->flags, 1}; continue; }
            uint64_t raw = 0;
            if (m3_read_at(c, x.slots[i], &raw, 8) || !raw) { unresolved++; continue; }
            uint64_t tg = c->maps[0].address + (raw & 0x3ffffffffULL);
            struct nameent kk = {.addr = tg};
            const struct nameent *ne = bsearch(&kk, t->names, t->nnames, sizeof *t->names, cmp_nameent);
            long ti = -1;
            for (uint32_t q = 0; q < c->nimgs; q++) if (tg >= c->imgs[q].text_addr && tg < c->imgs[q].text_addr + c->imgs[q].text_size) { ti = (long)q; break; }
            if (ne && ti >= 0 && ti != ci) pairs[np++] = (struct pair){c->imgs[ti].path, ne->name, x.sites[i], 0, 0};
            else own++;
        }
        qsort(pairs, np, sizeof *pairs, cmp_pair);
        size_t distinct = 0, sys = 0;
        for (size_t i = 0; i < np; i++) {
            if (i && !cmp_pair(&pairs[i], &pairs[i - 1])) { pairs[distinct - 1].sites += pairs[i].sites; continue; }
            pairs[distinct++] = pairs[i];
        }
        for (size_t i = 0; i < distinct; i++) {
            printf("I\t%s\t%s\t%s\t%" PRIu64, paths[k], pairs[i].exporter, pairs[i].name, pairs[i].sites);
            if (pairs[i].has_flags) {
                struct pv4_fixup d = pv4_decode_flags(pairs[i].flags);
                printf("\tgot-slot %s key %s addrDiv %u div %#x", d.authenticated ? "auth" : "plain", d.authenticated ? (d.key ? "DA" : "IA") : "-", d.usesAddressDiversity, d.discriminator);
            } else printf("\tslot of the importing image");
            printf("\n");
            if (!strncmp(pairs[i].exporter, "/usr/lib/system/", 16) || !strcmp(pairs[i].exporter, "/usr/lib/libSystem.B.dylib")) sys++;
        }
        printf("S\t%s\tslot_refs %zu\timport_pairs %zu\tfrom_libSystem_family %zu\tnot_imports_or_empty %zu\n", paths[k], x.n, distinct, sys, unresolved + own);
        free(pairs); free(x.slots); free(x.sites);
    }
    free(b);
    return 0;
}

#endif
