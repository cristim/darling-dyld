#include "check.h"
#include "enc.h"
#include "../a64.h"

static struct a64_state run(const uint32_t *w, size_t n)
{
    struct a64_state s;
    a64_init(&s);
    a64_feed(&s, w, n, 0x180000000ULL);
    return s;
}
static int has_acc(const struct a64_state *s, int32_t off, uint8_t size, char kind, uint64_t count)
{
    for (unsigned i = 0; i < s->nacc; i++)
        if (s->acc[i].off == off && s->acc[i].size == size && s->acc[i].kind == kind && s->acc[i].count == count) return 1;
    return 0;
}

static void test_counts(void)
{
    uint32_t w[] = {e_svc80(), e_nop(), e_mrs_tpidrro(8), e_and_imm_x(8, 8), e_mrs_tpidrro(9), e_nop(), e_svc80(), e_ret()};
    struct a64_state s = run(w, sizeof w / 4);
    CHECK_EQ(s.svc, 2);
    CHECK_EQ(s.tsd_inplace, 1);
    CHECK_EQ(s.tsd_other, 1);
    CHECK_EQ(s.insns, 7);  // the AND after an in-place mrs is consumed with it
}

static void test_commpage_three_step(void)
{
    // movz x3,#0xc000; movk x3,#0xffff,lsl16; movk x3,#0xf,lsl32; ldrb w2,[x3,#0x90]; ldr x4,[x3,#0x10]; ldrh w5,[x3,#0x26]; ret
    uint32_t w[] = {e_movz(1, 3, 0xc000, 0), e_movk(1, 3, 0xffff, 1), e_movk(1, 3, 0xf, 2), e_ldrb(2, 3, 0x90), e_ldr_x(4, 3, 0x10), e_ldrh(5, 3, 0x26), e_ret()};
    struct a64_state s = run(w, sizeof w / 4);
    CHECK_EQ(s.cp_sites, 1);
    CHECK_EQ(s.cp_with_access, 1);
    CHECK(has_acc(&s, 0x90, 1, 'L', 1));
    CHECK(has_acc(&s, 0x10, 8, 'L', 1));
    CHECK(has_acc(&s, 0x26, 2, 'L', 1));
    CHECK_EQ(s.nacc, 3);
}

static void test_commpage_offset_in_constant_and_alias(void)
{
    // address with the offset folded in (0xFFFFFC0A0), then add alias and a 32-bit load through the alias
    uint32_t w[] = {e_movz(1, 8, 0xc0a0, 0), e_movk(1, 8, 0xffff, 1), e_movk(1, 8, 0xf, 2), e_ldr_x(9, 8, 0), e_add_imm(10, 8, 8), e_ldr_w(11, 10, 4), e_ret()};
    struct a64_state s = run(w, sizeof w / 4);
    CHECK_EQ(s.cp_sites, 1);
    CHECK(has_acc(&s, 0xa0, 8, 'L', 1));
    CHECK(has_acc(&s, 0xa0 + 8 + 4, 4, 'L', 1));
}

static void test_commpage_negatives(void)
{
    // a plain constant that is not in the commpage range, and a base that is overwritten before use
    uint32_t w1[] = {e_movz(1, 3, 0xc000, 0), e_movk(1, 3, 0xffff, 1), e_ldr_x(4, 3, 0), e_ret()};
    struct a64_state s = run(w1, sizeof w1 / 4);
    CHECK_EQ(s.cp_sites, 0);
    uint32_t w2[] = {e_movz(1, 3, 0xc000, 0), e_movk(1, 3, 0xffff, 1), e_movk(1, 3, 0xf, 2), e_ldr_x(3, 4, 0), e_ldr_x(5, 3, 8), e_ret()};
    s = run(w2, sizeof w2 / 4);
    CHECK_EQ(s.cp_sites, 1);
    CHECK_EQ(s.cp_with_access, 0);  // x3 reloaded from memory, the second load is not through the commpage
    uint32_t w3[] = {e_movz(1, 3, 0xc000, 0), e_movk(1, 3, 0xffff, 1), e_movk(1, 3, 0xf, 2), e_bl(4), e_ldr_x(5, 3, 8), e_ret()};
    s = run(w3, sizeof w3 / 4);
    CHECK_EQ(s.cp_with_access, 0);  // a call ends the window
}

static void test_commpage_other_orders(void)
{
    // movz of the high part first, then movk: any order of the three pieces
    uint32_t w1[] = {e_movz(1, 6, 0xf, 2), e_movk(1, 6, 0xffff, 1), e_movk(1, 6, 0xc010, 0), e_ldr_x(7, 6, 0), e_ret()};
    struct a64_state s = run(w1, sizeof w1 / 4);
    CHECK_EQ(s.cp_sites, 1);
    CHECK(has_acc(&s, 0x10, 8, 'L', 1));
    // 32-bit movz/movk for the low half, 64-bit movk for the top
    uint32_t w2[] = {e_movz(0, 6, 0xc000, 0), e_movk(0, 6, 0xffff, 1), e_movk(1, 6, 0xf, 2), e_ldrb(7, 6, 0x91), e_ret()};
    s = run(w2, sizeof w2 / 4);
    CHECK_EQ(s.cp_sites, 1);
    CHECK(has_acc(&s, 0x91, 1, 'L', 1));
    // movn forms the all-ones high part: ~0xf0000 000... is not a commpage address, no site
    uint32_t w3[] = {e_movn(1, 6, 0x3fff, 0), e_ldr_x(7, 6, 0), e_ret()};
    s = run(w3, sizeof w3 / 4);
    CHECK_EQ(s.cp_sites, 0);
}

static void test_commpage_movk_only(void)
{
    // three movk without a movz (the register was zeroed or defined earlier): the other halves count as zero
    uint32_t w[] = {e_movk(1, 0, 0xc0d0, 0), e_movk(1, 0, 0xffff, 1), e_movk(1, 0, 0xf, 2), e_ldr_w(1, 0, 4), e_ret()};
    struct a64_state s = run(w, sizeof w / 4);
    CHECK_EQ(s.cp_sites, 1);
    CHECK(has_acc(&s, 0xd0 + 4, 4, 'L', 1));
    // two halves only: not a commpage address
    uint32_t w2[] = {e_movk(1, 0, 0xc0d0, 0), e_movk(1, 0, 0xffff, 1), e_ldr_w(1, 0, 4), e_ret()};
    s = run(w2, sizeof w2 / 4);
    CHECK_EQ(s.cp_sites, 0);
    // a stale half (more than 8 instructions old) does not combine with a later movk
    uint32_t w3[16] = {e_movk(1, 0, 0xc0d0, 0), e_movk(1, 0, 0xffff, 1)};
    for (int i = 2; i < 14; i++) w3[i] = e_nop();
    w3[14] = e_movk(1, 0, 0xf, 2);
    w3[15] = e_ret();
    s = run(w3, 16);
    CHECK_EQ(s.cp_sites, 0);
}

static void test_commpage_register_reused(void)
{
    // x3 holds the commpage base, then is reloaded with a constant outside the page: the later load is not a commpage read
    uint32_t w[] = {e_movz(1, 3, 0xc000, 0), e_movk(1, 3, 0xffff, 1), e_movk(1, 3, 0xf, 2), e_ldr_x(4, 3, 0x10), e_movz(1, 3, 0x5, 0), e_ldr_x(5, 3, 0x40), e_ret()};
    struct a64_state s = run(w, sizeof w / 4);
    CHECK_EQ(s.cp_sites, 1);
    CHECK_EQ(s.nacc, 1);
    CHECK(has_acc(&s, 0x10, 8, 'L', 1));
}

static void test_commpage_window_expires(void)
{
    uint32_t w[64] = {e_movz(1, 3, 0xc000, 0), e_movk(1, 3, 0xffff, 1), e_movk(1, 3, 0xf, 2)};
    for (int i = 3; i < 63; i++) w[i] = e_nop();
    w[63] = e_ldr_x(4, 3, 0);
    struct a64_state s = run(w, 64);
    CHECK_EQ(s.cp_sites, 1);
    CHECK_EQ(s.cp_with_access, 0);
}

static void test_pools(void)
{
    // ldr x1, <pool> then a load through x1; and adrp+ldr form
    struct a64_pool pool[2] = {{0x180000100ULL, 0x10}, {0x180001008ULL, 0x90}};
    uint32_t w[] = {e_ldr_lit(1, 0x180000000ULL, 0x180000100ULL), e_ldr_x(2, 1, 0), e_adrp(3, 0x180000008ULL, 0x180001000ULL), e_ldr_x(4, 3, 8), e_ldrb(5, 4, 0x20), e_ret()};
    struct a64_state s;
    a64_init(&s);
    s.pools = pool;
    s.npools = 2;
    s.skip_movwide = 1;
    a64_feed(&s, w, sizeof w / 4, 0x180000000ULL);
    CHECK_EQ(s.cp_sites, 2);
    CHECK(has_acc(&s, 0x10, 8, 'L', 1));
    CHECK(has_acc(&s, 0x90 + 0x20, 1, 'L', 1));
}

struct refs { uint64_t slot[8]; unsigned n; };
static void on_ref(void *c, uint64_t pc, uint64_t slot) { struct refs *r = c; (void)pc; if (r->n < 8) r->slot[r->n++] = slot; }

static void test_slotrefs(void)
{
    // stub shape: adrp x17,P; add x17,x17,#0x20; ldr x16,[x17]; then a plain adrp x8,P; ldr x8,[x8,#0x18]
    uint64_t base = 0x190000000ULL;
    uint32_t w[] = {e_adrp(17, base, 0x1e0004000ULL), e_add_imm(17, 17, 0x20), e_ldr_x(16, 17, 0), e_adrp(8, base + 12, 0x1e0004000ULL), e_ldr_x(8, 8, 0x18),
                    e_adrp(9, base + 20, 0x1e0004000ULL), e_mov_x(9, 1), e_ldr_x(9, 9, 0x10), e_ret()};
    struct a64_state s;
    struct refs r = {0};
    a64_init(&s);
    s.slotref = on_ref;
    s.slotref_ctx = &r;
    a64_feed(&s, w, sizeof w / 4, base);
    CHECK_EQ(r.n, 2);  // the third pair is broken by the overwrite of x9
    CHECK_EQ(r.slot[0], 0x1e0004020ULL);
    CHECK_EQ(r.slot[1], 0x1e0004018ULL);
}

int main(void)
{
    test_counts();
    test_commpage_three_step();
    test_commpage_offset_in_constant_and_alias();
    test_commpage_negatives();
    test_commpage_other_orders();
    test_commpage_movk_only();
    test_commpage_register_reused();
    test_commpage_window_expires();
    test_pools();
    test_slotrefs();
    TEST_DONE();
}
