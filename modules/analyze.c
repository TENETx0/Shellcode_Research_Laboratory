#define _GNU_SOURCE
#include "common.h"
#include "modules.h"

#include <stdlib.h>
#include <string.h>

void help_analyze(void)
{
    printf(
"Purpose:  Heuristic profiling of a (possibly raw) shellcode blob.\n"
"Syntax:   srl analyze <file> [--bad LIST]\n"
"Args:\n"
"  <file>     input file\n"
"  --bad LIST comma-separated hex bytes to flag, e.g. 00,0a,0d\n"
"             (default set: 00,0a,0d)\n"
"Reports:   length, byte-value coverage, NOP-sled candidates, presence of\n"
"           user-specified bad characters, top opcode-byte frequencies and a\n"
"           coarse architecture guess. These are statistical heuristics, not\n"
"           a disassembler verdict.\n"
"Example:   srl analyze sc.bin --bad 00,0a\n");
}

/* very coarse arch hint from common single-byte markers */
static const char *arch_hint(const unsigned char *b, size_t n)
{
    size_t x86 = 0, arm = 0;
    for (size_t i = 0; i + 1 < n; i++) {
        unsigned char c = b[i];
        if (c==0x55 || c==0x89 || c==0xe8 || c==0xff || c==0xcd) x86++;       /* push/mov/call/int */
        if ((b[i+1]&0xf0)==0xe0 && (c==0x00||c==0x10))           arm++;       /* loose ARM branch  */
    }
    if (x86 == 0 && arm == 0) return "indeterminate";
    return (x86 >= arm) ? "x86/x86-64 (heuristic)" : "ARM (heuristic)";
}

int cmd_analyze(int argc, char **argv)
{
    if (srl_wants_help(argc, argv) || argc < 1) { help_analyze(); return argc < 1; }

    const char *file = NULL, *badlist = "00,0a,0d";
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--bad") && i+1 < argc) badlist = argv[++i];
        else if (argv[i][0] != '-') file = argv[i];
    }
    if (!file) { fprintf(stderr, "error: no input file\n"); return 1; }

    size_t n = 0;
    unsigned char *b = srl_read_file(file, &n);
    if (!b) { fprintf(stderr, "error: cannot read %s\n", file); return 1; }

    size_t freq[256];
    srl_byte_freq(b, n, freq);

    printf("Architecture   : %s\n", arch_hint(b, n));
    printf("Length         : %zu bytes\n", n);
    printf("Entropy        : %.4f bits/byte\n", srl_shannon_entropy(b, n));

    /* NOP sled detection: longest run of 0x90 */
    size_t run = 0, best = 0, best_off = 0;
    for (size_t i = 0; i < n; i++) {
        if (b[i] == 0x90) { if (++run > best) { best = run; best_off = i - run + 1; } }
        else run = 0;
    }
    if (best >= 4) printf("NOP Sled       : %zu x 0x90 at offset 0x%zx\n", best, best_off);
    else           printf("NOP Sled       : none (>=4) detected\n");

    /* bad characters present */
    printf("Bad Characters :");
    int found = 0;
    char *dup = strdup(badlist), *save = NULL;
    for (char *t = strtok_r(dup, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        unsigned v = (unsigned)strtoul(t, NULL, 16);
        if (v < 256 && freq[v]) { printf(" 0x%02x", v); found = 1; }
    }
    free(dup);
    if (!found) printf(" none of the flagged set present");
    printf("\n");

    /* top opcode bytes */
    int order[256];
    for (int i = 0; i < 256; i++) order[i] = i;
    for (int i = 0; i < 256; i++)        /* simple selection of top 8 */
        for (int j = i + 1; j < 256; j++)
            if (freq[order[j]] > freq[order[i]]) { int t = order[i]; order[i] = order[j]; order[j] = t; }

    printf("Top Opcode Bytes:\n");
    for (int i = 0; i < 8 && freq[order[i]]; i++)
        printf("  0x%02x  %zu (%.1f%%)\n", order[i], freq[order[i]],
               100.0 * (double)freq[order[i]] / (double)n);

    free(b);
    return 0;
}
