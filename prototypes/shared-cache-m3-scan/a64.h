// Small AArch64 pattern matchers for the M3 3.0b scan. No I/O, no cache access: words in, counts out.
//   - svc #0x80 and `mrs Xt, TPIDRRO_EL0` counts (same rules as prototypes/shared-cache-p1/m0b_scan.c)
//   - commpage base formation (movz/movn/movk, or three movk on a register defined earlier with the other halves
//     counted as zero, building an address in [0xFFFFFC000, 0x1000000000)) and the loads/stores through the
//     formed register within a short window (absolute commpage offsets)
//   - adrp + add/ldr slot references (used to find the GOT slot behind a stub or a code reference)
// Heuristic by design: a window of A64_WINDOW instructions, registers killed by common writes and by any
// call/return/unconditional branch; it counts sites, it does not prove reachability.
#ifndef A64_H
#define A64_H
#include <stdint.h>
#include <string.h>

#define A64_COMMPAGE_BASE 0xFFFFFC000ULL
#define A64_COMMPAGE_END 0x1000000000ULL
#define A64_WINDOW 24
#define A64_MAX_ACC 512
#define A64_MAX_OPEN 8
#define A64_NREC 64

struct a64_access {
    int32_t off;        // offset from the commpage base; INT32_MIN when the offset is a register
    uint8_t size;       // access size in bytes (0 for register-offset forms)
    char kind;          // 'L' load, 'S' store, 'P' prefetch, 'R' register-offset, 'A' address escapes (add into another register is tracked, not counted)
    uint64_t count;
};

typedef void (*a64_slotref_fn)(void *ctx, uint64_t pc, uint64_t slot_addr);

// 8-byte literals (address in the image, offset from the commpage base) that hold a commpage address:
// a load of one of them (ldr literal, or adrp+ldr/add) opens a commpage register like a mov-wide sequence does.
struct a64_pool { uint64_t addr; int64_t off; };

struct a64_state {
    uint64_t insns, svc, tsd_inplace, tsd_other;
    uint64_t formed[8], formed_n[8];  // distinct constants formed by mov-wide sequences whose bits 32.. equal 0xf (cross-check)
    unsigned nformed;
    uint64_t hi_f, hi_ffff;  // mov-wide halves of the commpage base seen anywhere: #0xf at bit 32, #0xffff at bit 16 (cross-check of the formation matcher)
    uint64_t cp_sites, cp_with_access;
    uint64_t acc_overflow;
    struct a64_access acc[A64_MAX_ACC];
    unsigned nacc;
    uint64_t idx;
    struct { int valid; uint64_t val; uint64_t at; unsigned cov; } mv[32];  // cov: bit per 16-bit half that a mov-wide chain defined
    struct { int reg; int64_t off; uint64_t born; unsigned rec; } open[A64_MAX_OPEN];
    unsigned nopen;
    unsigned next_rec;
    int rec_hit[A64_NREC];
    struct { int valid; uint64_t page; uint64_t at; } pg[32];
    a64_slotref_fn slotref;
    void *slotref_ctx;
    const struct a64_pool *pools;
    unsigned npools;
    int skip_movwide;  // pool-only pass: do not look for mov-wide sequences again
};

static inline const struct a64_pool *a64_pool_at(const struct a64_state *s, uint64_t addr)
{
    for (unsigned i = 0; i < s->npools; i++)
        if (s->pools[i].addr == addr) return &s->pools[i];
    return 0;
}

static inline void a64_init(struct a64_state *s) { memset(s, 0, sizeof *s); }

static inline void a64_note_access(struct a64_state *s, int32_t off, uint8_t size, char kind, unsigned rec)
{
    for (unsigned i = 0; i < s->nacc; i++)
        if (s->acc[i].off == off && s->acc[i].size == size && s->acc[i].kind == kind) { s->acc[i].count++; goto done; }
    if (s->nacc < A64_MAX_ACC) s->acc[s->nacc++] = (struct a64_access){off, size, kind, 1};
    else s->acc_overflow++;
done:
    if (!s->rec_hit[rec]) { s->rec_hit[rec] = 1; s->cp_with_access++; }
}

static inline void a64_close_entry(struct a64_state *s, unsigned i) { s->open[i] = s->open[--s->nopen]; }

static inline void a64_open_entry(struct a64_state *s, int reg, int64_t off, unsigned rec)
{
    for (unsigned i = 0; i < s->nopen; i++)
        if (s->open[i].reg == reg) { s->open[i].off = off; s->open[i].born = s->idx; s->open[i].rec = rec; return; }
    if (s->nopen == A64_MAX_OPEN) a64_close_entry(s, 0);
    s->open[s->nopen++] = (typeof(s->open[0])){reg, off, s->idx, rec};
}

static inline void a64_kill_reg(struct a64_state *s, int reg)
{
    for (unsigned i = 0; i < s->nopen; i++)
        if (s->open[i].reg == reg) { a64_close_entry(s, i); return; }
}

// Decode one load/store against base register `rn`; returns 1 and fills the outputs when x is one.
static inline int a64_ldst_base(uint32_t x, int *rn, int64_t *imm, uint8_t *size, char *kind)
{
    *rn = (x >> 5) & 31;
    uint32_t sz = x >> 30, opc = (x >> 22) & 3, v = (x >> 26) & 1;
    if ((x & 0x3B000000u) == 0x39000000u) { // unsigned scaled imm12
        unsigned scale = sz;
        if (v && sz == 0 && (opc & 2)) scale = 4;
        *imm = (int64_t)((x >> 10) & 0xFFF) << scale;
        *size = (uint8_t)(1u << scale);
        *kind = (!v && sz == 3 && opc == 2) ? 'P' : (v ? (opc & 1) : (opc != 0)) ? 'L' : 'S';
        return 1;
    }
    if ((x & 0x3B200C00u) == 0x38000000u) { // unscaled imm9 (ldur/stur)
        *imm = ((int64_t)(int32_t)(x << 11)) >> 23;
        unsigned scale = sz;
        if (v && sz == 0 && (opc & 2)) scale = 4;
        *size = (uint8_t)(1u << scale);
        *kind = (v ? (opc & 1) : (opc != 0)) ? 'L' : 'S';
        return 1;
    }
    if ((x & 0x3B200C00u) == 0x38200800u) { // register offset
        *imm = INT32_MIN;
        *size = 0;
        *kind = 'R';
        return 1;
    }
    if ((x & 0x3A000000u) == 0x28000000u) { // ldp/stp (offset, pre, post)
        unsigned mode = (x >> 23) & 3;
        unsigned scale = v ? 2 + sz : 2 + (sz >> 1);
        *imm = (((int64_t)(int32_t)(x << 10)) >> 25) * (int64_t)(1u << scale);
        if (mode == 1) *imm = 0; // post-index accesses the base itself
        *size = (uint8_t)(2u << scale);
        *kind = (x >> 22) & 1 ? 'L' : 'S';
        return 1;
    }
    return 0;
}

// Does instruction x overwrite general register `reg` (common encodings only)?
static inline int a64_writes(uint32_t x, int reg)
{
    uint32_t cls = (x >> 25) & 0xF;
    if (cls == 8 || cls == 9) return (int)(x & 31) == reg;                  // data processing, immediate
    if (cls == 5 || cls == 13) return (int)(x & 31) == reg && ((x & 0x1FE00000u) != 0x1A400000u); // data processing, register (not ccmp)
    if ((cls & 5) == 4) {                                                     // loads and stores
        int l = (x >> 22) & 1;
        if (l && !((x >> 26) & 1) && (int)(x & 31) == reg) return 1;
        if ((x & 0x3A000000u) == 0x28000000u && l && !((x >> 26) & 1) && (int)((x >> 10) & 31) == reg) return 1;
        if (((x & 0x3B200C00u) == 0x38000400u || (x & 0x3B200C00u) == 0x38000C00u) && (int)((x >> 5) & 31) == reg) return 1; // writeback
        return 0;
    }
    return 0;
}

static inline int a64_is_flow_break(uint32_t x)
{
    return (x & 0xFC000000u) == 0x14000000u || (x & 0xFC000000u) == 0x94000000u || (x & 0xFE000000u) == 0xD6000000u;
}

static inline void a64_feed(struct a64_state *s, const uint32_t *w, size_t n, uint64_t pc0)
{
    for (size_t k = 0; k < n; k++) {
        uint32_t x = w[k];
        uint64_t pc = pc0 + k * 4;
        s->idx++;
        s->insns++;
        if (x == 0xD4001001u) { s->svc++; continue; }
        if ((x & 0xFFFFFFE0u) == 0xD53BD060u) {
            uint32_t rt = x & 31, nx = k + 1 < n ? w[k + 1] : 0;
            if ((nx & 0xFFC00000u) == 0x92400000u && (nx & 31) == rt && ((nx >> 5) & 31) == rt) { s->tsd_inplace++; k++; s->idx++; }
            else s->tsd_other++;
            continue;
        }
        // expire open commpage entries and adrp state
        for (unsigned i = 0; i < s->nopen;)
            if (s->idx - s->open[i].born > A64_WINDOW) a64_close_entry(s, i); else i++;
        if (a64_is_flow_break(x)) { s->nopen = 0; }
        // loads/stores through an open entry
        for (unsigned i = 0; i < s->nopen; i++) {
            int rn; int64_t imm; uint8_t size; char kind;
            if (a64_ldst_base(x, &rn, &imm, &size, &kind) && rn == s->open[i].reg)
                a64_note_access(s, imm == INT32_MIN ? INT32_MIN : (int32_t)(s->open[i].off + imm), size, kind, s->open[i].rec);
        }
        // adrp slot references and pool loads
        if ((x & 0xFF000000u) == 0x58000000u && s->npools) { // ldr Xt, <literal>
            const struct a64_pool *pl = a64_pool_at(s, pc + (uint64_t)(((int64_t)(int32_t)(x << 8) >> 13) * 4));
            if (pl && (x & 31) != 31) {
                unsigned rec = s->next_rec++ % A64_NREC;
                s->rec_hit[rec] = 0;
                s->cp_sites++;
                a64_kill_reg(s, (int)(x & 31));
                a64_open_entry(s, (int)(x & 31), pl->off, rec);
            }
            continue;
        }
        if (s->slotref || s->npools) {
            // registers written by this instruction lose their adrp state unless a handler below sets it again
            uint32_t killmask = 0;
            for (unsigned r = 0; r < 31; r++)
                if (s->pg[r].valid && a64_writes(x, (int)r)) killmask |= 1u << r;
            if ((x & 0x9F000000u) == 0x90000000u) {
                int64_t imm = (int64_t)(((x >> 29) & 3) | (((x >> 5) & 0x7FFFF) << 2));
                imm = (imm << 43) >> 43;
                s->pg[x & 31].valid = 1;
                s->pg[x & 31].page = (pc & ~0xFFFULL) + (uint64_t)(imm << 12);
                s->pg[x & 31].at = s->idx;
            } else if ((x & 0xFFC00000u) == 0xF9400000u) { // ldr Xt, [Xn, #imm]
                int rn = (x >> 5) & 31;
                if (s->pg[rn].valid && s->idx - s->pg[rn].at <= 8) {
                    uint64_t slot = s->pg[rn].page + (((x >> 10) & 0xFFF) << 3);
                    if (s->slotref) s->slotref(s->slotref_ctx, pc, slot);
                    const struct a64_pool *pl = s->npools ? a64_pool_at(s, slot) : 0;
                    if (pl && (x & 31) != 31) {
                        unsigned rec = s->next_rec++ % A64_NREC;
                        s->rec_hit[rec] = 0;
                        s->cp_sites++;
                        a64_kill_reg(s, (int)(x & 31));
                        a64_open_entry(s, (int)(x & 31), pl->off, rec);
                        s->pg[x & 31].valid = 0;
                        continue;  // the load wrote x{Rt}; do not let the generic kill below close the new entry
                    }
                }
                if (s->pg[x & 31].valid && (x & 31) != (unsigned)rn) s->pg[x & 31].valid = 0;
            } else if ((x & 0xFF800000u) == 0x91000000u) { // add Xd, Xn, #imm
                int rn = (x >> 5) & 31, rd = x & 31;
                if (s->pg[rn].valid && s->idx - s->pg[rn].at <= 8) {
                    uint64_t imm = ((x >> 10) & 0xFFF) << (((x >> 22) & 1) ? 12 : 0);
                    s->pg[rd].valid = 1;
                    s->pg[rd].page = s->pg[rn].page + imm;
                    s->pg[rd].at = s->idx;
                }
            }
            for (unsigned r = 0; r < 31; r++)
                if ((killmask >> r & 1) && s->pg[r].at != s->idx) s->pg[r].valid = 0;
        }
        if ((x & 0x5F9FFFE0u) == 0x528001E0u && ((x >> 21) & 3) == 2 && (x >> 31)) s->hi_f++;   // movz/movk Xd, #0xf, lsl #32
        if ((x & 0x5F9FFFE0u) == 0x529FFFE0u && ((x >> 21) & 3) == 1) s->hi_ffff++;           // movz/movk Xd, #0xffff, lsl #16
        // mov-wide chains building a commpage address
        if (!s->skip_movwide && (x & 0x1F800000u) == 0x12800000u && ((x >> 29) & 3) != 1) {
            unsigned opc = (x >> 29) & 3, sh = ((x >> 21) & 3) * 16, rd = x & 31;
            int sf = (int)(x >> 31);
            uint64_t imm = ((x >> 5) & 0xFFFF);
            uint64_t mask = sf ? ~0ULL : 0xFFFFFFFFULL;
            if (rd != 31) {
                if (opc == 2) { s->mv[rd].valid = 1; s->mv[rd].val = (imm << sh) & mask; s->mv[rd].at = s->idx; s->mv[rd].cov = 0xF; }
                else if (opc == 0) { s->mv[rd].valid = 1; s->mv[rd].val = ~(imm << sh) & mask; s->mv[rd].at = s->idx; s->mv[rd].cov = 0xF; }
                else { // movk; on a register this chain did not define (the compiler may have zeroed it earlier) the other halves count as zero
                    if (!(s->mv[rd].valid && s->idx - s->mv[rd].at <= 8)) { s->mv[rd].valid = 1; s->mv[rd].val = 0; s->mv[rd].cov = 0; }
                    s->mv[rd].val = ((s->mv[rd].val & ~(0xFFFFULL << sh)) | (imm << sh)) & mask;
                    s->mv[rd].cov |= 1u << (sh / 16);
                    s->mv[rd].at = s->idx;
                }
                if (s->mv[rd].valid && (s->mv[rd].cov & 7) == 7 && (s->mv[rd].val >> 32) == 0xf) {
                    unsigned q = 0;
                    while (q < s->nformed && s->formed[q] != s->mv[rd].val) q++;
                    if (q == s->nformed && q < 8) { s->formed[q] = s->mv[rd].val; s->formed_n[q] = 0; s->nformed++; }
                    if (q < 8) s->formed_n[q]++;
                }
                a64_kill_reg(s, (int)rd);
                if (s->mv[rd].valid && s->mv[rd].val >= A64_COMMPAGE_BASE && s->mv[rd].val < A64_COMMPAGE_END) {
                    unsigned rec = s->next_rec++ % A64_NREC;
                    s->rec_hit[rec] = 0;
                    s->cp_sites++;
                    a64_open_entry(s, (int)rd, (int64_t)(s->mv[rd].val - A64_COMMPAGE_BASE), rec);
                }
            }
            continue;
        }
        // aliases of an open register: add Xd, Xn, #imm and mov Xd, Xn
        int handled = 0;
        if ((x & 0xFF800000u) == 0x91000000u) {
            int rn = (x >> 5) & 31, rd = x & 31;
            for (unsigned i = 0; i < s->nopen && !handled; i++)
                if (s->open[i].reg == rn && rd != 31) {
                    int64_t off = s->open[i].off + (int64_t)(((x >> 10) & 0xFFF) << (((x >> 22) & 1) ? 12 : 0));
                    unsigned rec = s->open[i].rec;
                    a64_open_entry(s, rd, off, rec);
                    handled = 1;
                }
        } else if ((x & 0xFFE0FFE0u) == 0xAA0003E0u) {
            int rm = (x >> 16) & 31, rd = x & 31;
            for (unsigned i = 0; i < s->nopen && !handled; i++)
                if (s->open[i].reg == rm && rd != 31) { a64_open_entry(s, rd, s->open[i].off, s->open[i].rec); handled = 1; }
        }
        if (!handled) {
            for (unsigned i = 0; i < s->nopen;)
                if (a64_writes(x, s->open[i].reg)) a64_close_entry(s, i); else i++;
        }
        // any other write invalidates a half-built mov-wide value
        if (!handled) {
            unsigned rd = x & 31;
            uint32_t cls = (x >> 25) & 0xF;
            if (cls == 8 || cls == 9 || cls == 5 || cls == 13) s->mv[rd].valid = 0;
        }
    }
}
#endif
