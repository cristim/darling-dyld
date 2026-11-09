// m3_exports <thin arm64 mach-o file>: list the exported symbols (export trie) and the install names of the
// re-exported dylibs of a Mach-O dylib on disk. Read-only. Output: "E\t<name>\t<flags>\t<reexport import name or ->",
// "R\t<install name>" per LC_REEXPORT_DYLIB, "I\t<install name>" for LC_ID_DYLIB.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "trie.h"

static void on_export(void *ctx, const char *name, uint64_t flags, uint64_t value, const char *imp)
{
    (void)ctx; (void)value;
    printf("E\t%s\t%#llx\t%s\n", name, (unsigned long long)flags, imp ? (*imp ? imp : "-") : "-");
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 2; }
    int fd = open(argv[1], O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st)) { perror(argv[1]); return 1; }
    const uint8_t *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED || st.st_size < 32) { fprintf(stderr, "cannot map %s\n", argv[1]); return 1; }
    uint32_t magic;
    memcpy(&magic, m, 4);
    if (magic != 0xfeedfacf) { fprintf(stderr, "%s: not a thin 64-bit little-endian Mach-O\n", argv[1]); return 1; }
    uint32_t ncmds, sizeofcmds;
    memcpy(&ncmds, m + 16, 4);
    memcpy(&sizeofcmds, m + 20, 4);
    if (32 + (uint64_t)sizeofcmds > (uint64_t)st.st_size) { fprintf(stderr, "bad load commands\n"); return 1; }
    const uint8_t *p = m + 32;
    uint32_t eoff = 0, esize = 0;
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd, sz;
        memcpy(&cmd, p, 4);
        memcpy(&sz, p + 4, 4);
        if (sz < 8 || p + sz > m + 32 + sizeofcmds) { fprintf(stderr, "bad load command\n"); return 1; }
        if (cmd == 0x80000033) { memcpy(&eoff, p + 8, 4); memcpy(&esize, p + 12, 4); }
        else if ((cmd == 0x22 || cmd == 0x80000022) && !esize) { memcpy(&eoff, p + 40, 4); memcpy(&esize, p + 44, 4); }
        else if (cmd == 0xd || cmd == 0x8000001f || cmd == 0x80000018) {
            uint32_t no;
            memcpy(&no, p + 8, 4);
            printf("%c\t%s\n", cmd == 0xd ? 'I' : 'R', (const char *)p + no);
        }
        p += sz;
    }
    if ((uint64_t)eoff + esize > (uint64_t)st.st_size) { fprintf(stderr, "export trie outside the file\n"); return 1; }
    long n = trie_walk(m + eoff, esize, on_export, NULL);
    if (n < 0) { fprintf(stderr, "%s: malformed export trie\n", argv[1]); return 1; }
    fprintf(stderr, "%ld exports\n", n);
    return 0;
}
