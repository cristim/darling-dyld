// Mach-O export trie reader (the format of LC_DYLD_EXPORTS_TRIE / the export part of LC_DYLD_INFO).
// Pure: a byte range in, one callback per exported symbol out. Malformed input (offsets outside the range,
// cycles, over-long names, truncated ULEBs) makes trie_walk return -1 instead of reading out of bounds.
#ifndef TRIE_H
#define TRIE_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TRIE_FLAGS_KIND_MASK 0x03u
#define TRIE_FLAGS_REEXPORT 0x08u
#define TRIE_FLAGS_STUB_AND_RESOLVER 0x10u
#define TRIE_MAX_NAME 1024
#define TRIE_MAX_DEPTH 64

// name: exported symbol; flags as in the trie; value: image offset (or ordinal for a re-export, stub offset for a
// stub-and-resolver); import_name: the re-exported symbol's name in the other image ("" = same name), else NULL.
typedef void (*trie_export_fn)(void *ctx, const char *name, uint64_t flags, uint64_t value, const char *import_name);

struct trie_walk_state {
    const uint8_t *t;
    size_t size;
    trie_export_fn fn;
    void *ctx;
    char name[TRIE_MAX_NAME + 1];
    long count;
    unsigned long nodes;
};

static inline int trie_uleb(const uint8_t *t, size_t size, size_t *pos, uint64_t *out)
{
    uint64_t v = 0;
    unsigned shift = 0;
    while (*pos < size) {
        uint8_t b = t[(*pos)++];
        if (shift < 64) v |= (uint64_t)(b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) { *out = v; return 0; }
    }
    return -1;
}

static inline int trie_node(struct trie_walk_state *s, size_t off, size_t namelen, unsigned depth)
{
    if (off >= s->size || depth > TRIE_MAX_DEPTH || ++s->nodes > 4000000ul) return -1;
    size_t pos = off;
    uint64_t term;
    if (trie_uleb(s->t, s->size, &pos, &term)) return -1;
    if (term > s->size - pos) return -1;
    size_t children = pos + (size_t)term;
    if (term) {
        uint64_t flags, v = 0;
        size_t p = pos;
        if (trie_uleb(s->t, s->size, &p, &flags)) return -1;
        const char *imp = NULL;
        if (flags & TRIE_FLAGS_REEXPORT) {
            if (trie_uleb(s->t, s->size, &p, &v)) return -1;
            size_t e = p;
            while (e < children && s->t[e]) e++;
            if (e >= children) return -1;
            imp = (const char *)s->t + p;
        } else if (trie_uleb(s->t, s->size, &p, &v)) return -1;
        s->name[namelen] = 0;
        s->fn(s->ctx, s->name, flags, v, imp);
        s->count++;
    }
    if (children >= s->size) return -1;
    unsigned nchild = s->t[children];
    pos = children + 1;
    for (unsigned i = 0; i < nchild; i++) {
        size_t e = pos;
        while (e < s->size && s->t[e]) e++;
        if (e >= s->size) return -1;
        size_t el = e - pos;
        if (namelen + el > TRIE_MAX_NAME) return -1;
        memcpy(s->name + namelen, s->t + pos, el);
        pos = e + 1;
        uint64_t child;
        if (trie_uleb(s->t, s->size, &pos, &child)) return -1;
        if (child >= s->size || child <= off) return -1;  // children always sit after their parent: rules out cycles
        if (trie_node(s, (size_t)child, namelen + el, depth + 1)) return -1;
    }
    return 0;
}

// returns the number of exports, or -1 when the trie is malformed
static inline long trie_walk(const uint8_t *t, size_t size, trie_export_fn fn, void *ctx)
{
    if (!size) return 0;
    struct trie_walk_state *s = (struct trie_walk_state *)__builtin_alloca(sizeof *s);
    memset(s, 0, sizeof *s);
    s->t = t; s->size = size; s->fn = fn; s->ctx = ctx;
    return trie_node(s, 0, 0, 0) ? -1 : s->count;
}
#endif
