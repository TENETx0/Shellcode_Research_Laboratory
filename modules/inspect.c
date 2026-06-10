#define _GNU_SOURCE
#include "common.h"
#include "modules.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

void help_inspect(void)
{
    printf(
"Purpose:  Identify a file and dump its structural metadata.\n"
"Syntax:   srl inspect <file> [--strings] [--hex N]\n"
"Args:\n"
"  <file>      input file\n"
"  --strings   print printable ASCII strings (min length 4)\n"
"  --hex N     hexdump the first N bytes (default 128)\n"
"Detects:    Linux ELF, Windows PE, and raw shellcode (fallback).\n"
"Output:     size, format, magic bytes, architecture, basic header fields.\n"
"Example:    srl inspect /bin/ls --strings\n");
}

static void show_elf(const unsigned char *b, size_t n)
{
    if (n < 20) return;
    int is64  = b[4] == 2;
    int le    = b[5] == 1;
    const char *cls  = is64 ? "ELF64" : "ELF32";
    const char *end  = le ? "little-endian" : "big-endian";
    unsigned type = le ? (unsigned)(b[16] | b[17]<<8) : (unsigned)(b[17] | b[16]<<8);
    unsigned mach = le ? (unsigned)(b[18] | b[19]<<8) : (unsigned)(b[19] | b[18]<<8);
    const char *arch = "unknown";
    switch (mach) {
        case 0x03: arch = "x86";     break;
        case 0x3e: arch = "x86-64";  break;
        case 0x28: arch = "ARM";     break;
        case 0xb7: arch = "AArch64"; break;
        case 0xf3: arch = "RISC-V";  break;
    }
    const char *tname = "?";
    switch (type) { case 1: tname="REL (object)"; break; case 2: tname="EXEC"; break;
                    case 3: tname="DYN (PIE/shared)"; break; case 4: tname="CORE"; break; }
    printf("Format         : %s (%s)\n", cls, end);
    printf("ELF Type       : %s\n", tname);
    printf("Architecture   : %s\n", arch);
}

static void show_pe(const unsigned char *b, size_t n)
{
    if (n < 0x40) return;
    unsigned peoff = (unsigned)(b[0x3c] | b[0x3d]<<8 | b[0x3e]<<16 | b[0x3f]<<24);
    if (peoff + 6 > n || !(b[peoff]=='P' && b[peoff+1]=='E')) {
        printf("Format         : MS-DOS / MZ (no PE header)\n");
        return;
    }
    unsigned mach = (unsigned)(b[peoff+4] | b[peoff+5]<<8);
    const char *arch = "unknown";
    switch (mach) {
        case 0x14c:  arch = "x86";     break;
        case 0x8664: arch = "x86-64";  break;
        case 0x1c0:  arch = "ARM";     break;
        case 0xaa64: arch = "ARM64";   break;
    }
    printf("Format         : Windows PE\n");
    printf("Architecture   : %s\n", arch);
}

static void print_strings(const unsigned char *b, size_t n)
{
    printf("\nStrings (min length 4):\n");
    size_t start = 0; int run = 0, shown = 0;
    for (size_t i = 0; i <= n; i++) {
        int pr = (i < n) && isprint(b[i]);
        if (pr) { if (run == 0) start = i; run++; }
        else {
            if (run >= 4 && shown < 40) {
                printf("  %08zx  %.*s\n", start, run, b + start);
                shown++;
            }
            run = 0;
        }
    }
    if (shown == 40) printf("  ... (truncated)\n");
}

int cmd_inspect(int argc, char **argv)
{
    if (srl_wants_help(argc, argv) || argc < 1) { help_inspect(); return argc < 1; }

    const char *file = NULL;
    int want_strings = 0; size_t hexn = 128;
    for (int i = 0; i < argc; i++) {
        if      (!strcmp(argv[i], "--strings")) want_strings = 1;
        else if (!strcmp(argv[i], "--hex") && i+1 < argc) hexn = (size_t)strtoul(argv[++i], NULL, 10);
        else if (argv[i][0] != '-') file = argv[i];
    }
    if (!file) { fprintf(stderr, "error: no input file\n"); return 1; }

    size_t n = 0;
    unsigned char *b = srl_read_file(file, &n);
    if (!b) { fprintf(stderr, "error: cannot read %s\n", file); return 1; }

    printf("File           : %s\n", srl_basename(file));
    printf("Size           : %zu bytes\n", n);
    printf("Magic Bytes    : ");
    for (size_t i = 0; i < 4 && i < n; i++) printf("%02x ", b[i]);
    printf("\n");

    if      (n >= 4 && b[0]==0x7f && b[1]=='E' && b[2]=='L' && b[3]=='F') show_elf(b, n);
    else if (n >= 2 && b[0]=='M' && b[1]=='Z')                           show_pe(b, n);
    else {
        printf("Format         : Raw shellcode / unknown blob\n");
        printf("Entropy        : %.4f bits/byte\n", srl_shannon_entropy(b, n));
    }

    printf("\nHex Dump (first %zu bytes):\n", hexn);
    srl_hexdump(b, n, hexn);

    if (want_strings) print_strings(b, n);

    free(b);
    return 0;
}
