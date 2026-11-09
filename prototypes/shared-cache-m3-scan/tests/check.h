// Minimal assertion helpers for the synthetic-fixture tests (no cache bytes anywhere in this directory).
#ifndef CHECK_H
#define CHECK_H
#include <stdio.h>
#include <stdlib.h>
static int g_failures;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); g_failures++; } } while (0)
#define CHECK_EQ(a, b) do { unsigned long long _a = (unsigned long long)(a), _b = (unsigned long long)(b); if (_a != _b) { fprintf(stderr, "FAIL %s:%d: %s == %s (%llu vs %llu)\n", __FILE__, __LINE__, #a, #b, _a, _b); g_failures++; } } while (0)
#define TEST_DONE() do { if (g_failures) { fprintf(stderr, "%d failure(s)\n", g_failures); return 1; } printf("ok\n"); return 0; } while (0)
#endif
