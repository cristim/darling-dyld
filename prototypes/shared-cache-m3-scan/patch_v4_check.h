// Pure validation and traversal of a version-4 patch info blob held in memory (patch_v4.h layout).
// No I/O: the blob, the image addresses and the mapping ranges are passed in, so tests use synthetic data.
#ifndef PATCH_V4_CHECK_H
#define PATCH_V4_CHECK_H
#include <stdio.h>
#include <string.h>
#include "patch_v4.h"

struct pv4_range { uint64_t lo, hi; };  // [lo, hi)

struct pv4_env {
    uint32_t nimages;
    const uint64_t *image_addr;           // per image index: address of its mach header
    uint64_t cache_base;                  // address that cache offsets are relative to
    const struct pv4_range *data;         // mapped data mappings (patch locations must lie inside)
    size_t ndata;
};

struct pv4_view {
    const uint8_t *blob;
    uint64_t base, size;  // address and byte size of the blob
    struct pv4_header h;
    const struct pv4_image_patches *patches;
    const struct pv4_image_export *exports;
    const struct pv4_client *clients;
    const struct pv4_client_export *clientExports;
    const struct pv4_location *locations;
    const struct pv4_got_clients *gotClients;
    const struct pv4_got_client_export *gotClientExports;
    const struct pv4_got_location *gotLocations;
    const char *names;
};

enum pv4_check {
    PV4_E_VERSION, PV4_E_ARRAY_BOUNDS, PV4_E_ARRAY_OVERLAP, PV4_E_ALIGN, PV4_E_TABLE_COUNT,
    PV4_E_CLIENTS_TILE, PV4_E_EXPORTS_TILE, PV4_E_CLIENT_IMAGE, PV4_E_CLIENTEXPORTS_TILE, PV4_E_EXPORT_INDEX,
    PV4_E_LOCATIONS_TILE, PV4_E_EXPORT_NAME, PV4_E_LOC_ADDR,
    PV4_E_GOT_TILE, PV4_E_GOT_EXPORT_INDEX, PV4_E_GOT_LOCATIONS_TILE, PV4_E_GOT_LOC_ADDR, PV4_E_GOT_RESERVED,
    PV4_E_COUNT
};
static const char *const pv4_check_name[PV4_E_COUNT] = {
    "version", "array-bounds", "array-overlap", "alignment", "table-count",
    "clients-tile", "exports-tile", "client-image", "clientExports-tile", "export-index",
    "locations-tile", "export-name", "location-address",
    "got-tile", "got-export-index", "gotLocations-tile", "got-location-address", "got-reserved"
};

struct pv4_report {
    uint64_t errors[PV4_E_COUNT];
    uint64_t first_bad[PV4_E_COUNT];  // index of the first offending record (or array number)
    uint64_t locations_seen, got_locations_seen, exports_seen;
};

static inline void pv4_fail(struct pv4_report *r, enum pv4_check c, uint64_t idx)
{
    if (!r->errors[c]++) r->first_bad[c] = idx;
}

static inline int pv4_in_ranges(const struct pv4_range *rg, size_t n, uint64_t a)
{
    for (size_t i = 0; i < n; i++)
        if (a >= rg[i].lo && a < rg[i].hi) return 1;
    return 0;
}

// Map the header and arrays inside the blob. Returns 0 on success, otherwise fills err.
static inline int pv4_open(struct pv4_view *v, const uint8_t *blob, uint64_t base, uint64_t size, char *err, size_t errsz)
{
    memset(v, 0, sizeof *v);
    if (size < sizeof v->h) { snprintf(err, errsz, "blob smaller than header"); return -1; }
    v->blob = blob; v->base = base; v->size = size;
    memcpy(&v->h, blob, sizeof v->h);
    struct { uint64_t addr, count, stride; const void **out; } a[] = {
        {v->h.patchTableArrayAddr, v->h.patchTableArrayCount, sizeof(struct pv4_image_patches), (const void **)&v->patches},
        {v->h.imageExportsArrayAddr, v->h.imageExportsArrayCount, sizeof(struct pv4_image_export), (const void **)&v->exports},
        {v->h.clientsArrayAddr, v->h.clientsArrayCount, sizeof(struct pv4_client), (const void **)&v->clients},
        {v->h.clientExportsArrayAddr, v->h.clientExportsArrayCount, sizeof(struct pv4_client_export), (const void **)&v->clientExports},
        {v->h.locationArrayAddr, v->h.locationArrayCount, sizeof(struct pv4_location), (const void **)&v->locations},
        {v->h.gotClientsArrayAddr, v->h.gotClientsArrayCount, sizeof(struct pv4_got_clients), (const void **)&v->gotClients},
        {v->h.gotClientExportsArrayAddr, v->h.gotClientExportsArrayCount, sizeof(struct pv4_got_client_export), (const void **)&v->gotClientExports},
        {v->h.gotLocationArrayAddr, v->h.gotLocationArrayCount, sizeof(struct pv4_got_location), (const void **)&v->gotLocations},
        {v->h.exportNamesAddr, v->h.exportNamesSize, 1, (const void **)&v->names},
    };
    for (unsigned i = 0; i < sizeof a / sizeof *a; i++) {
        uint64_t len = a[i].count * a[i].stride;
        if (a[i].count && len / a[i].stride != a[i].count) { snprintf(err, errsz, "array %u size overflows", i); return -1; }
        if (a[i].addr < base + sizeof v->h || a[i].addr > base + size || len > base + size - a[i].addr) {
            snprintf(err, errsz, "array %u [%#llx +%#llx) outside the blob", i, (unsigned long long)a[i].addr, (unsigned long long)len);
            return -1;
        }
        if (a[i].addr % 4) { snprintf(err, errsz, "array %u not 4-byte aligned", i); return -1; }
        *a[i].out = blob + (a[i].addr - base);
    }
    return 0;
}

// Full consistency pass; counts violations per check in r (r is zeroed first).
static inline void pv4_validate(const struct pv4_view *v, const struct pv4_env *env, struct pv4_report *r)
{
    memset(r, 0, sizeof *r);
    const struct pv4_header *h = &v->h;
    if (h->patchTableVersion != PV4_VERSION || h->patchLocationVersion != 0) pv4_fail(r, PV4_E_VERSION, 0);
    if (h->patchTableArrayCount != env->nimages || h->gotClientsArrayCount != env->nimages) pv4_fail(r, PV4_E_TABLE_COUNT, 0);
    // arrays must not overlap each other
    struct pv4_range ar[9];
    uint64_t cnt[9] = {h->patchTableArrayCount, h->imageExportsArrayCount, h->clientsArrayCount, h->clientExportsArrayCount, h->locationArrayCount,
                       h->gotClientsArrayCount, h->gotClientExportsArrayCount, h->gotLocationArrayCount, h->exportNamesSize};
    uint64_t str[9] = {16, 8, 12, 12, 8, 8, 12, 16, 1};
    uint64_t adr[9] = {h->patchTableArrayAddr, h->imageExportsArrayAddr, h->clientsArrayAddr, h->clientExportsArrayAddr, h->locationArrayAddr,
                       h->gotClientsArrayAddr, h->gotClientExportsArrayAddr, h->gotLocationArrayAddr, h->exportNamesAddr};
    for (int i = 0; i < 9; i++) ar[i] = (struct pv4_range){adr[i], adr[i] + cnt[i] * str[i]};
    for (int i = 0; i < 9; i++)
        for (int j = i + 1; j < 9; j++)
            if (ar[i].lo < ar[j].hi && ar[j].lo < ar[i].hi) pv4_fail(r, PV4_E_ARRAY_OVERLAP, (uint64_t)i * 16 + (uint64_t)j);

    uint64_t next_client = 0, next_export = 0, next_cexp = 0, next_loc = 0, next_gexp = 0, next_gloc = 0;
    for (uint32_t i = 0; i < h->patchTableArrayCount; i++) {
        const struct pv4_image_patches *p = &v->patches[i];
        if (p->clientsStartIndex != next_client || p->clientsStartIndex + (uint64_t)p->clientsCount > h->clientsArrayCount) pv4_fail(r, PV4_E_CLIENTS_TILE, i);
        next_client = (uint64_t)p->clientsStartIndex + p->clientsCount;
        if (p->exportsStartIndex != next_export || p->exportsStartIndex + (uint64_t)p->exportsCount > h->imageExportsArrayCount) pv4_fail(r, PV4_E_EXPORTS_TILE, i);
        next_export = (uint64_t)p->exportsStartIndex + p->exportsCount;
        for (uint64_t j = p->clientsStartIndex; j < next_client && j < h->clientsArrayCount; j++) {
            const struct pv4_client *c = &v->clients[j];
            if (c->clientDylibIndex >= env->nimages) pv4_fail(r, PV4_E_CLIENT_IMAGE, j);
            if (c->exportsStartIndex != next_cexp || c->exportsStartIndex + (uint64_t)c->exportsCount > h->clientExportsArrayCount) pv4_fail(r, PV4_E_CLIENTEXPORTS_TILE, j);
            next_cexp = (uint64_t)c->exportsStartIndex + c->exportsCount;
            for (uint64_t k = c->exportsStartIndex; k < next_cexp && k < h->clientExportsArrayCount; k++) {
                const struct pv4_client_export *e = &v->clientExports[k];
                if (e->imageExportIndex < p->exportsStartIndex || e->imageExportIndex - p->exportsStartIndex >= p->exportsCount) pv4_fail(r, PV4_E_EXPORT_INDEX, k);
                for (uint64_t l = e->locationsStartIndex; c->clientDylibIndex < env->nimages && l < (uint64_t)e->locationsStartIndex + e->locationsCount && l < h->locationArrayCount; l++) {
                    r->locations_seen++;
                    if (!pv4_in_ranges(env->data, env->ndata, env->image_addr[c->clientDylibIndex] + v->locations[l].dylibOffsetOfUse)) pv4_fail(r, PV4_E_LOC_ADDR, l);
                }
                if (e->locationsStartIndex != next_loc || e->locationsStartIndex + (uint64_t)e->locationsCount > h->locationArrayCount) pv4_fail(r, PV4_E_LOCATIONS_TILE, k);
                next_loc = (uint64_t)e->locationsStartIndex + e->locationsCount;
            }
        }
        const struct pv4_got_clients *g = &v->gotClients[i < h->gotClientsArrayCount ? i : 0];
        if (i < h->gotClientsArrayCount) {
            if (g->exportsStartIndex != next_gexp || g->exportsStartIndex + (uint64_t)g->exportsCount > h->gotClientExportsArrayCount) pv4_fail(r, PV4_E_GOT_TILE, i);
            next_gexp = (uint64_t)g->exportsStartIndex + g->exportsCount;
            for (uint64_t k = g->exportsStartIndex; k < next_gexp && k < h->gotClientExportsArrayCount; k++) {
                const struct pv4_got_client_export *e = &v->gotClientExports[k];
                if (e->imageExportIndex < p->exportsStartIndex || e->imageExportIndex - p->exportsStartIndex >= p->exportsCount) pv4_fail(r, PV4_E_GOT_EXPORT_INDEX, k);
                if (e->locationsStartIndex != next_gloc || e->locationsStartIndex + (uint64_t)e->locationsCount > h->gotLocationArrayCount) pv4_fail(r, PV4_E_GOT_LOCATIONS_TILE, k);
                next_gloc = (uint64_t)e->locationsStartIndex + e->locationsCount;
            }
        }
    }
    if (next_client != h->clientsArrayCount) pv4_fail(r, PV4_E_CLIENTS_TILE, ~0ull);
    if (next_export != h->imageExportsArrayCount) pv4_fail(r, PV4_E_EXPORTS_TILE, ~0ull);
    if (next_cexp != h->clientExportsArrayCount) pv4_fail(r, PV4_E_CLIENTEXPORTS_TILE, ~0ull);
    if (next_loc != h->locationArrayCount) pv4_fail(r, PV4_E_LOCATIONS_TILE, ~0ull);
    if (next_gexp != h->gotClientExportsArrayCount) pv4_fail(r, PV4_E_GOT_TILE, ~0ull);
    if (next_gloc != h->gotLocationArrayCount) pv4_fail(r, PV4_E_GOT_LOCATIONS_TILE, ~0ull);

    for (uint64_t i = 0; i < h->imageExportsArrayCount; i++) {
        uint32_t off = PV4_NAME_OFFSET(v->exports[i].nameKind);
        r->exports_seen++;
        if (off >= h->exportNamesSize || !memchr(v->names + off, 0, h->exportNamesSize - off)) pv4_fail(r, PV4_E_EXPORT_NAME, i);
    }
    for (uint64_t i = 0; i < h->gotLocationArrayCount; i++) {
        const struct pv4_got_location *g = &v->gotLocations[i];
        r->got_locations_seen++;
        if (!pv4_in_ranges(env->data, env->ndata, env->cache_base + (((uint64_t)g->cacheOffsetHi << 32) | g->cacheOffsetLo))) pv4_fail(r, PV4_E_GOT_LOC_ADDR, i);
        if (g->reserved) pv4_fail(r, PV4_E_GOT_RESERVED, i);
    }
}

// Visit every patch location of a validated table. For plain locations `client` is the client image index;
// for GOT locations it is PV4_NO_CLIENT (the GOT table does not name clients; the address identifies them).
#define PV4_NO_CLIENT 0xffffffffu
typedef void (*pv4_loc_fn)(void *ctx, uint32_t exporter, uint32_t export_index, int is_got, uint32_t client, uint64_t addr, uint32_t flags);

static inline void pv4_walk(const struct pv4_view *v, const struct pv4_env *env, pv4_loc_fn fn, void *ctx)
{
    for (uint32_t i = 0; i < v->h.patchTableArrayCount; i++) {
        const struct pv4_image_patches *p = &v->patches[i];
        for (uint64_t j = p->clientsStartIndex; j < (uint64_t)p->clientsStartIndex + p->clientsCount; j++) {
            const struct pv4_client *c = &v->clients[j];
            for (uint64_t k = c->exportsStartIndex; k < (uint64_t)c->exportsStartIndex + c->exportsCount; k++) {
                const struct pv4_client_export *e = &v->clientExports[k];
                for (uint64_t l = e->locationsStartIndex; l < (uint64_t)e->locationsStartIndex + e->locationsCount; l++)
                    fn(ctx, i, e->imageExportIndex, 0, c->clientDylibIndex, env->image_addr[c->clientDylibIndex] + v->locations[l].dylibOffsetOfUse, v->locations[l].flags);
            }
        }
        if (i >= v->h.gotClientsArrayCount) continue;
        const struct pv4_got_clients *g = &v->gotClients[i];
        for (uint64_t k = g->exportsStartIndex; k < (uint64_t)g->exportsStartIndex + g->exportsCount; k++) {
            const struct pv4_got_client_export *e = &v->gotClientExports[k];
            for (uint64_t l = e->locationsStartIndex; l < (uint64_t)e->locationsStartIndex + e->locationsCount; l++) {
                const struct pv4_got_location *gl = &v->gotLocations[l];
                fn(ctx, i, e->imageExportIndex, 1, PV4_NO_CLIENT, env->cache_base + (((uint64_t)gl->cacheOffsetHi << 32) | gl->cacheOffsetLo), gl->flags);
            }
        }
    }
}

static inline const char *pv4_export_name(const struct pv4_view *v, uint32_t export_index)
{
    return v->names + PV4_NAME_OFFSET(v->exports[export_index].nameKind);
}
#endif
