#include <string.h>
#include "check.h"
#include "../trie.h"

struct rec { char name[64]; uint64_t flags, value; char imp[64]; int has_imp; };
struct got { struct rec r[16]; int n; };
static void on(void *c, const char *name, uint64_t flags, uint64_t value, const char *imp)
{
    struct got *g = c;
    struct rec *r = &g->r[g->n++];
    snprintf(r->name, sizeof r->name, "%s", name);
    r->flags = flags; r->value = value; r->has_imp = imp != NULL;
    snprintf(r->imp, sizeof r->imp, "%s", imp ? imp : "");
}
static const struct rec *find(const struct got *g, const char *name)
{
    for (int i = 0; i < g->n; i++) if (!strcmp(g->r[i].name, name)) return &g->r[i];
    return NULL;
}

// Fixture: root with two edges, one shared prefix: "_foo" (addr 0x10), "_fob" (re-export of "_x" from ordinal 2) and "_z" (addr 0x20).
static uint8_t trie[64];
static size_t build_good(void)
{
    size_t n = 0;
    trie[n++] = 0x00; trie[n++] = 0x02;                          // root, 2 children
    size_t e1 = n; memcpy(trie + n, "_fo\0", 4); n += 4; size_t p1 = n++;
    size_t e2 = n; memcpy(trie + n, "_z\0", 3); n += 3; size_t p2 = n++;
    (void)e1; (void)e2;
    trie[p1] = (uint8_t)n;                                       // node "_fo"
    trie[n++] = 0x00; trie[n++] = 0x02;
    memcpy(trie + n, "o\0", 2); n += 2; size_t q1 = n++;
    memcpy(trie + n, "b\0", 2); n += 2; size_t q2 = n++;
    trie[q1] = (uint8_t)n;                                       // "_foo": address 0x10
    trie[n++] = 0x02; trie[n++] = 0x00; trie[n++] = 0x10; trie[n++] = 0x00;
    trie[q2] = (uint8_t)n;                                       // "_fob": reexport ordinal 2 of "_x": terminal = flags 8, ordinal 2, "_x\0"
    trie[n++] = 0x05; trie[n++] = TRIE_FLAGS_REEXPORT; trie[n++] = 0x02; memcpy(trie + n, "_x\0", 3); n += 3; trie[n++] = 0x00;
    trie[p2] = (uint8_t)n;                                       // "_z": address 0x20
    trie[n++] = 0x02; trie[n++] = 0x00; trie[n++] = 0x20; trie[n++] = 0x00;
    return n;
}

static void test_good(void)
{
    size_t n = build_good();
    struct got g = {0};
    CHECK_EQ(trie_walk(trie, n, on, &g), 3);
    CHECK_EQ(g.n, 3);
    const struct rec *r = find(&g, "_foo");
    CHECK(r && r->value == 0x10 && r->flags == 0 && !r->has_imp);
    r = find(&g, "_fob");
    CHECK(r && (r->flags & TRIE_FLAGS_REEXPORT) && r->value == 2 && r->has_imp && !strcmp(r->imp, "_x"));
    r = find(&g, "_z");
    CHECK(r && r->value == 0x20);
}

static void test_empty_and_malformed(void)
{
    struct got g = {0};
    CHECK_EQ(trie_walk(trie, 0, on, &g), 0);
    size_t n = build_good();
    // child offset pointing outside the range
    uint8_t bad[64];
    memcpy(bad, trie, n);
    bad[6] = 0x7f;  // "_fo" edge offset (index: 2 + 4 = 6)
    CHECK_EQ(trie_walk(bad, n, on, &g), -1);
    // child offset pointing back at the root (cycle)
    memcpy(bad, trie, n);
    bad[6] = 0x00;
    CHECK_EQ(trie_walk(bad, n, on, &g), -1);
    // truncated: cut inside the first edge string
    CHECK_EQ(trie_walk(trie, 4, on, &g), -1);
    // terminal size larger than the remaining data
    memcpy(bad, trie, n);
    bad[0] = 0x7f;
    CHECK_EQ(trie_walk(bad, n, on, &g), -1);
    // unterminated ULEB at the end of the data
    uint8_t cut[] = {0x00, 0x01, 'a', 0, 0x80};
    CHECK_EQ(trie_walk(cut, sizeof cut, on, &g), -1);
}

static void test_wrapping_terminal_size(void)
{
    // terminal size 2^64-1 (ULEB) makes `pos + size` wrap back into the data; a reader that does not check it
    // would continue at the wrapped position and report a valid empty trie
    uint8_t t[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 'a', 0, 13, 0x00, 0x00};
    struct got g = {0};
    CHECK_EQ(trie_walk(t, sizeof t, on, &g), -1);
}

static void test_reexport_name_must_end_inside_terminal(void)
{
    // root -> "_q" -> node whose terminal (flags 8, ordinal 2, "x") ends before the string's NUL; the NUL it would
    // find belongs to the children count byte
    uint8_t t[] = {0x00, 0x01, '_', 'q', 0, 6, 0x03, TRIE_FLAGS_REEXPORT, 0x02, 'x', 0x00};
    struct got g = {0};
    CHECK_EQ(trie_walk(t, sizeof t, on, &g), -1);
}

static void test_backward_reference(void)
{
    // root: "a" -> leaf at 9, "b" -> node at 13. Two edges to the same forward leaf would be fine, but the node at 13
    // points back at the leaf at 9: tries written by ld64 only point forward, and a back-reference is how cycles start
    uint8_t t[] = {0x00, 0x02, 'a', 0, 9, 'b', 0, 13, 0x00, 0x02, 0x00, 0x10, 0x00, 0x00, 0x01, 'c', 0, 9};
    struct got g = {0};
    CHECK_EQ(trie_walk(t, sizeof t, on, &g), -1);
    uint8_t ok[] = {0x00, 0x02, 'a', 0, 9, 'b', 0, 9, 0x00, 0x02, 0x00, 0x10, 0x00};
    CHECK_EQ(trie_walk(ok, sizeof ok, on, &g), 2);   // a leaf shared by two edges is fine
}

static void test_depth_limit(void)
{
    // a chain of single-character edges deeper than TRIE_MAX_DEPTH (nodes of 6 bytes, 2-byte ULEB child offsets)
    uint8_t t[600];
    size_t n = 0;
    for (int i = 0; i < TRIE_MAX_DEPTH + 4; i++) {
        size_t child = n + 6;
        t[n++] = 0x00; t[n++] = 0x01; t[n++] = 'a'; t[n++] = 0;
        t[n++] = (uint8_t)((child & 0x7f) | 0x80); t[n++] = (uint8_t)(child >> 7);
    }
    t[n++] = 0x00; t[n++] = 0x00;
    struct got g = {0};
    CHECK_EQ(trie_walk(t, n, on, &g), -1);
}

int main(void)
{
    test_good();
    test_empty_and_malformed();
    test_backward_reference();
    test_depth_limit();
    test_wrapping_terminal_size();
    test_reexport_name_must_end_inside_terminal();
    TEST_DONE();
}
