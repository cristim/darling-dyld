// text and dataq modes: svc/TSD counts and commpage formation/literals in code and data. Included by m3_scan.c only.
#ifndef MODE_TEXT_H
#define MODE_TEXT_H
// text <from> <to> [only-file] : per image whose __TEXT starts in [from,to): svc/TSD counts, commpage base formations and the
// commpage offsets accessed through them, 8-byte literals that look like commpage addresses (whole __TEXT segment)
struct lit { int64_t off; uint64_t count; };
struct pools { struct a64_pool p[64]; unsigned n; };
static void lit_add(struct lit *l, unsigned *n, int64_t off)
{
    for (unsigned i = 0; i < *n; i++) if (l[i].off == off) { l[i].count++; return; }
    if (*n < 64) l[(*n)++] = (struct lit){off, 1};
}
static int cmp_sec(const void *a, const void *b) { const struct m3_sec *x = a, *y = b; return x->addr < y->addr ? -1 : x->addr > y->addr; }

static void scan_qwords(const uint8_t *buf, size_t len, uint64_t base, struct lit *l, unsigned *nl, uint64_t *total, struct pools *pl)
{
    size_t k = (size_t)((8 - (base & 7)) & 7);
    for (; k + 8 <= len; k += 8) {
        uint64_t q = m3_rd64(buf + k);
        if (q >= A64_COMMPAGE_BASE && q < A64_COMMPAGE_END) {
            lit_add(l, nl, (int64_t)(q - A64_COMMPAGE_BASE));
            (*total)++;
            if (pl->n < 64) pl->p[pl->n++] = (struct a64_pool){base + k, (int64_t)(q - A64_COMMPAGE_BASE)};
        }
    }
}

static int mode_text(struct m3_cache *c, uint64_t from, uint64_t to, const char *only_file)
{
    static uint8_t buf[4u << 20];
    uint64_t scanned = 0, insns = 0;
    char *only = NULL; // optional file of install names, one per line: scan just those images
    if (only_file) {
        FILE *f = fopen(only_file, "r");
        if (!f) m3_die(only_file);
        only = calloc(c->nimgs, 1);
        char line[400];
        while (fgets(line, sizeof line, f)) { line[strcspn(line, "\n")] = 0; long i = m3_find_image(c, line); if (i >= 0) only[i] = 1; }
        fclose(f);
    }
    for (uint32_t ii = 0; ii < c->nimgs; ii++) {
        struct m3_image *im = &c->imgs[ii];
        if (im->text_addr < from || im->text_addr >= to) continue;
        if (only && !only[ii]) continue;
        scanned++;
        struct a64_state st;
        a64_init(&st);
        struct lit lits[64];
        struct pools pools = {.n = 0};
        unsigned nl = 0;
        uint64_t lit_total = 0;
        struct m3_sec secs[M3_MAX_SECS];
        memcpy(secs, im->secs, sizeof secs);
        qsort(secs, (size_t)im->nsec, sizeof secs[0], cmp_sec);
        uint64_t cur = im->text_addr, end = im->text_addr + im->text_size;
        for (int s = 0; s <= im->nsec; s++) {
            uint64_t gap_end = s < im->nsec ? secs[s].addr : end;
            for (; cur < gap_end; ) { // non-code bytes: literal scan only
                size_t len = gap_end - cur < sizeof buf ? (size_t)(gap_end - cur) : sizeof buf;
                if (m3_read_at(c, cur, buf, len)) m3_die("text gap read");
                scan_qwords(buf, len, cur, lits, &nl, &lit_total, &pools);
                cur += len;
            }
            if (s == im->nsec) break;
            for (uint64_t off = 0; off < secs[s].size; off += sizeof buf) {
                size_t len = secs[s].size - off < sizeof buf ? (size_t)(secs[s].size - off) : sizeof buf;
                len &= ~(size_t)3;
                uint64_t a = secs[s].addr + off;
                if (!len) break;
                if (m3_read_at(c, a, buf, len)) m3_die("text read");
                a64_feed(&st, (const uint32_t *)buf, len / 4, a);
                scan_qwords(buf, len, a, lits, &nl, &lit_total, &pools);
            }
            cur = secs[s].addr + secs[s].size;
            st.nopen = 0;
            memset(st.mv, 0, sizeof st.mv);
        }
        insns += st.insns;
        struct a64_state st2;
        a64_init(&st2);
        if (pools.n) { // second pass over the code: loads of the pool qwords (ldr literal / adrp+ldr) open commpage registers
            st2.pools = pools.p;
            st2.npools = pools.n;
            st2.skip_movwide = 1;
            for (int s = 0; s < im->nsec; s++) {
                for (uint64_t off = 0; off < secs[s].size; off += sizeof buf) {
                    size_t len = secs[s].size - off < sizeof buf ? (size_t)(secs[s].size - off) : sizeof buf;
                    len &= ~(size_t)3;
                    if (!len) break;
                    if (m3_read_at(c, secs[s].addr + off, buf, len)) m3_die("text read (pass 2)");
                    a64_feed(&st2, (const uint32_t *)buf, len / 4, secs[s].addr + off);
                }
                st2.nopen = 0;
                memset(st2.pg, 0, sizeof st2.pg);
            }
        }
        printf("P\t%s\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\n", im->path, st.insns, st.svc, st.tsd_inplace, st.tsd_other, st.cp_sites, st.cp_with_access, lit_total);
        if (st.nacc) {
            printf("O\t%s\t", im->path);
            for (unsigned i = 0; i < st.nacc; i++) printf("%s%d:%u:%c:%" PRIu64, i ? "," : "", st.acc[i].off, st.acc[i].size, st.acc[i].kind, st.acc[i].count);
            printf("\n");
        }
        if (st.hi_f || st.hi_ffff) {
            printf("H\t%s\t%" PRIu64 "\t%" PRIu64 "\t", im->path, st.hi_f, st.hi_ffff);
            for (unsigned q = 0; q < st.nformed; q++) printf("%s%#" PRIx64 ":%" PRIu64, q ? "," : "", st.formed[q], st.formed_n[q]);
            printf("\n");
        }
        if (st2.nacc) {
            printf("W\t%s\t%" PRIu64 "\t%" PRIu64 "\t", im->path, st2.cp_sites, st2.cp_with_access);
            for (unsigned i = 0; i < st2.nacc; i++) printf("%s%d:%u:%c:%" PRIu64, i ? "," : "", st2.acc[i].off, st2.acc[i].size, st2.acc[i].kind, st2.acc[i].count);
            printf("\n");
        } else if (st2.cp_sites) printf("W\t%s\t%" PRIu64 "\t0\t\n", im->path, st2.cp_sites);
        if (nl) {
            printf("Q\t%s\t", im->path);
            for (unsigned i = 0; i < nl; i++) printf("%s%" PRId64 ":%" PRIu64, i ? "," : "", lits[i].off, lits[i].count);
            printf("\n");
        }
    }
    printf("C scanned_images %" PRIu64 "\nC insns %" PRIu64 "\n", scanned, insns);
    return 0;
}


// dataq <path>...: 8-byte words in the data segments (everything but __TEXT and __LINKEDIT) that look like commpage addresses
static int mode_dataq(struct m3_cache *c, int n, char **paths)
{
    static uint8_t buf[1u << 20];
    for (int k = 0; k < n; k++) {
        long ci = m3_find_image(c, paths[k]);
        if (ci < 0) { printf("X\t%s\tnot in cache\n", paths[k]); continue; }
        struct seg segs[16];
        int ns = image_segments(c, ci, segs, 16);
        struct lit lits[64];
        unsigned nl = 0;
        uint64_t total = 0, bytes = 0;
        struct pools pl = {.n = 0};
        for (int s = 0; s < ns; s++) {
            if (!strcmp(segs[s].name, "__TEXT") || !strcmp(segs[s].name, "__LINKEDIT")) continue;
            for (uint64_t off = 0; off < segs[s].vmsize; off += sizeof buf) {
                size_t len = segs[s].vmsize - off < sizeof buf ? (size_t)(segs[s].vmsize - off) : sizeof buf;
                if (m3_read_at(c, segs[s].vmaddr + off, buf, len)) break; // segment extends past the mapping: stop
                scan_qwords(buf, len, segs[s].vmaddr + off, lits, &nl, &total, &pl);
                bytes += len;
            }
        }
        printf("D\t%s\tdata bytes %" PRIu64 "\tcommpage-like words %" PRIu64 "\t", paths[k], bytes, total);
        for (unsigned i = 0; i < nl; i++) printf("%s%" PRId64 ":%" PRIu64, i ? "," : "", lits[i].off, lits[i].count);
        printf("\n");
    }
    return 0;
}

#endif
