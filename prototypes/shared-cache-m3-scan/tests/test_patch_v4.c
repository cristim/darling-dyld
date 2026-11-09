#include <string.h>
#include "check.h"
#include "../patch_v4_check.h"

// Synthetic patch table: image 0 exports "_foo" and "_bar"; image 1 and image 2 are its clients.
//   plain locations: image 1 uses _foo twice, image 2 uses _bar once; two GOT locations of _bar (one above 4 GiB from the cache base).
#define BASE 0x7000000000ULL
#define CACHE_BASE 0x180000000ULL
static uint8_t blob[4096];
static uint64_t blob_size;
static const uint64_t image_addr[3] = {0x180000000ULL, 0x180100000ULL, 0x180200000ULL};
static const struct pv4_range data[2] = {{0x190000000ULL, 0x190100000ULL}, {0x2a0000000ULL, 0x2a0100000ULL}};

static void put32(uint64_t addr, uint32_t v) { memcpy(blob + (addr - BASE), &v, 4); }
static void put64(uint64_t addr, uint64_t v) { memcpy(blob + (addr - BASE), &v, 8); }
static uint32_t get32(uint64_t addr) { uint32_t v; memcpy(&v, blob + (addr - BASE), 4); return v; }

// array addresses (all 4-byte aligned, inside the blob)
enum { A_PT = BASE + 0x98, A_IE = A_PT + 3 * 16, A_CL = A_IE + 2 * 8, A_CE = A_CL + 2 * 12, A_LO = A_CE + 2 * 12, A_GC = A_LO + 3 * 8,
       A_GE = A_GC + 3 * 8, A_GL = A_GE + 1 * 12, A_NM = A_GL + 2 * 16 };

static void build(void)
{
    memset(blob, 0, sizeof blob);
    uint64_t h[19] = {PV4_VERSION, A_PT, 3, A_IE, 2, A_CL, 2, A_CE, 2, A_LO, 3, A_NM, 10, A_GC, 3, A_GE, 1, A_GL, 2};
    memcpy(blob, &h[0], 8);
    memcpy(blob + 8, &h[1], 18 * 8);
    // patchTable: image 0 has clients [0,2), exports [0,2); the others have nothing
    uint32_t pt[3][4] = {{0, 2, 0, 2}, {2, 0, 2, 0}, {2, 0, 2, 0}};
    for (int i = 0; i < 3; i++) for (int k = 0; k < 4; k++) put32(A_PT + (uint64_t)i * 16 + 4 * k, pt[i][k]);
    // imageExports: _foo at +0x100 (name 0), _bar at +0x200 (name 5, kind 8)
    put32(A_IE, 0x100); put32(A_IE + 4, 0);
    put32(A_IE + 8, 0x200); put32(A_IE + 12, 5 | 0x80000000u);
    // clients: image 1 -> clientExports [0,1); image 2 -> [1,2)
    put32(A_CL, 1); put32(A_CL + 4, 0); put32(A_CL + 8, 1);
    put32(A_CL + 12, 2); put32(A_CL + 16, 1); put32(A_CL + 20, 1);
    // clientExports (absolute export index): image 1 uses export 0 with locations [0,2); image 2 uses export 1 with [2,3)
    put32(A_CE, 0); put32(A_CE + 4, 0); put32(A_CE + 8, 2);
    put32(A_CE + 12, 1); put32(A_CE + 16, 2); put32(A_CE + 20, 1);
    // locations: offset from the client image to its data, flags = authenticated IA with address diversity
    put32(A_LO, 0x190000000ULL - 0x180100000ULL + 0x10); put32(A_LO + 4, 0x4001);
    put32(A_LO + 8, 0x190000000ULL - 0x180100000ULL + 0x18); put32(A_LO + 12, 0x4001);
    put32(A_LO + 16, 0x190000000ULL - 0x180200000ULL + 0x20); put32(A_LO + 20, 0x6ae1c001u);
    // gotClients: image 0 has the only GOT export record
    uint32_t gc[3][2] = {{0, 1}, {1, 0}, {1, 0}};
    for (int i = 0; i < 3; i++) { put32(A_GC + (uint64_t)i * 8, gc[i][0]); put32(A_GC + (uint64_t)i * 8 + 4, gc[i][1]); }
    put32(A_GE, 1); put32(A_GE + 4, 0); put32(A_GE + 8, 2);  // export 1 (_bar), gotLocations [0,2)
    put32(A_GL, 0x190000040ULL - CACHE_BASE); put32(A_GL + 4, 0); put32(A_GL + 8, 0x4001); put32(A_GL + 12, 0);
    put32(A_GL + 16, (uint32_t)((0x2a0000080ULL - CACHE_BASE) & 0xffffffffu)); put32(A_GL + 20, 1); put32(A_GL + 24, 0x4001); put32(A_GL + 28, 0);  // above 4 GiB: high word 1
    memcpy(blob + (A_NM - BASE), "_foo\0_bar\0", 10);
    blob_size = A_NM - BASE + 10;
    (void)put64;
}

static struct pv4_env env(void) { return (struct pv4_env){3, image_addr, CACHE_BASE, data, 2}; }

static struct pv4_report check_blob(int *open_rc)
{
    struct pv4_view v;
    char err[100];
    struct pv4_report r;
    memset(&r, 0, sizeof r);
    *open_rc = pv4_open(&v, blob, BASE, blob_size, err, sizeof err);
    if (*open_rc == 0) { struct pv4_env e = env(); pv4_validate(&v, &e, &r); }
    return r;
}
static uint64_t total(const struct pv4_report *r) { uint64_t t = 0; for (int i = 0; i < PV4_E_COUNT; i++) t += r->errors[i]; return t; }

static void expect_only(const char *what, enum pv4_check c)
{
    int rc;
    struct pv4_report r = check_blob(&rc);
    if (rc) { fprintf(stderr, "FAIL %s: pv4_open rejected the blob\n", what); g_failures++; return; }
    if (!r.errors[c]) { fprintf(stderr, "FAIL %s: check %s did not fire (total %llu)\n", what, pv4_check_name[c], (unsigned long long)total(&r)); g_failures++; }
}

struct seen { int n; uint32_t exporter[8], xi[8], client[8]; int got[8]; uint64_t addr[8]; };
static void on_loc(void *c, uint32_t exporter, uint32_t xi, int is_got, uint32_t client, uint64_t addr, uint32_t flags)
{
    struct seen *s = c;
    (void)flags;
    if (s->n < 8) { s->exporter[s->n] = exporter; s->xi[s->n] = xi; s->got[s->n] = is_got; s->client[s->n] = client; s->addr[s->n] = addr; s->n++; }
}

static void test_valid_and_walk(void)
{
    build();
    int rc;
    struct pv4_report r = check_blob(&rc);
    CHECK_EQ(rc, 0);
    for (int i = 0; i < PV4_E_COUNT; i++) if (r.errors[i]) fprintf(stderr, "unexpected violation %s at %llu\n", pv4_check_name[i], (unsigned long long)r.first_bad[i]);
    CHECK_EQ(total(&r), 0);
    CHECK_EQ(r.locations_seen, 3);
    CHECK_EQ(r.got_locations_seen, 2);
    CHECK_EQ(r.exports_seen, 2);
    struct pv4_view v;
    char err[100];
    CHECK_EQ(pv4_open(&v, blob, BASE, blob_size, err, sizeof err), 0);
    struct pv4_env e = env();
    struct seen s = {0};
    pv4_walk(&v, &e, on_loc, &s);
    CHECK_EQ(s.n, 5);
    CHECK_EQ(s.addr[0], 0x190000010ULL);
    CHECK_EQ(s.client[0], 1);
    CHECK_EQ(s.xi[0], 0);
    CHECK_EQ(s.addr[2], 0x190000020ULL);
    CHECK_EQ(s.client[2], 2);
    CHECK_EQ(s.xi[2], 1);
    CHECK(s.got[3]);
    CHECK_EQ(s.addr[3], 0x190000040ULL);
    CHECK_EQ(s.client[3], PV4_NO_CLIENT);
    CHECK(s.got[4]);
    CHECK_EQ(s.addr[4], 0x2a0000080ULL);
    CHECK(!strcmp(pv4_export_name(&v, 0), "_foo"));
    CHECK(!strcmp(pv4_export_name(&v, 1), "_bar"));
    CHECK_EQ(PV4_NAME_KIND(v.exports[1].nameKind), 8);
}

static void test_mutations(void)
{
    build(); put32(BASE, 3); expect_only("version 3", PV4_E_VERSION);
    build(); put32(BASE + 4, 1); expect_only("location version", PV4_E_VERSION);
    build(); put32(A_PT + 4, 3); expect_only("clients count too big", PV4_E_CLIENTS_TILE);
    build(); put32(A_PT + 16 + 0, 1); expect_only("clients start not contiguous", PV4_E_CLIENTS_TILE);
    build(); put32(A_PT + 8, 1); expect_only("exports start not contiguous", PV4_E_EXPORTS_TILE);
    build(); put32(A_CL, 7); expect_only("client image index invalid", PV4_E_CLIENT_IMAGE);
    build(); put32(A_CL + 4, 1); expect_only("clientExports slice shifted", PV4_E_CLIENTEXPORTS_TILE);
    build(); put32(A_CE, 2); expect_only("export index outside the exporter's slice", PV4_E_EXPORT_INDEX);
    build(); put32(A_CE + 4, 1); expect_only("locations slice shifted", PV4_E_LOCATIONS_TILE);
    build(); put32(A_IE + 12, 0x0fffffffu); expect_only("name offset outside the blob", PV4_E_EXPORT_NAME);
    build(); put32(A_LO, 0x10); expect_only("location outside the data mappings", PV4_E_LOC_ADDR);
    build(); put32(A_GL, 0x1000); expect_only("GOT location outside the data mappings", PV4_E_GOT_LOC_ADDR);
    build(); put32(A_GL + 12, 1); expect_only("GOT reserved word set", PV4_E_GOT_RESERVED);
    build(); put32(A_GC + 4, 2); expect_only("GOT slice too long", PV4_E_GOT_TILE);
    build(); put32(A_GE, 5); expect_only("GOT export index outside the slice", PV4_E_GOT_EXPORT_INDEX);
    build(); put32(A_GE + 4, 1); expect_only("GOT locations slice shifted", PV4_E_GOT_LOCATIONS_TILE);
    build(); put32(A_GL + 20, 0); expect_only("high word of a GOT offset dropped", PV4_E_GOT_LOC_ADDR);
    build(); blob[A_NM - BASE + 9] = 'r'; expect_only("unterminated export name", PV4_E_EXPORT_NAME);
    build(); put64(BASE + 8 + 8, 5); expect_only("patchTable count differs from the image count", PV4_E_TABLE_COUNT);
    build(); put64(BASE + 8 + 2 * 8, A_PT + 8); expect_only("arrays overlap", PV4_E_ARRAY_OVERLAP);
}

static void test_open_rejects(void)
{
    build();
    struct pv4_view v;
    char err[100];
    CHECK(pv4_open(&v, blob, BASE, 100, err, sizeof err) != 0);                       // smaller than the header
    CHECK(pv4_open(&v, blob, BASE, blob_size - 1, err, sizeof err) != 0);             // name blob runs past the end
    build(); put64(BASE + 8, A_PT + 2);
    CHECK(pv4_open(&v, blob, BASE, blob_size, err, sizeof err) != 0);                 // misaligned array
    build(); put64(BASE + 8 + 8, 0x4000000000000000ULL);
    CHECK(pv4_open(&v, blob, BASE, blob_size, err, sizeof err) != 0);                 // count * stride overflows
    build();
    CHECK_EQ(get32(BASE), PV4_VERSION);
}

static void test_flags(void)
{
    struct pv4_fixup d = pv4_decode_flags(0x6ae1c001u);
    CHECK(d.authenticated && d.key == 1 && d.usesAddressDiversity && d.discriminator == 0x6ae1 && d.addend == 0);
    d = pv4_decode_flags(0x4001u);
    CHECK(d.authenticated && d.key == 0 && d.usesAddressDiversity && d.discriminator == 0);
    d = pv4_decode_flags(0xa001u);
    CHECK(d.authenticated && d.key == 1 && !d.usesAddressDiversity && d.addend == 16);
    d = pv4_decode_flags(0x9000u);
    CHECK(!d.authenticated && d.addend == 72);
    d = pv4_decode_flags(0x80u);
    CHECK(!d.authenticated && d.high7 == 0x40 && d.addend == 0);
    d = pv4_decode_flags(0x100u);
    CHECK(d.bit8 && !d.authenticated && d.addend == 0);
}

int main(void)
{
    test_valid_and_walk();
    test_mutations();
    test_open_rejects();
    test_flags();
    TEST_DONE();
}
