#define _GNU_SOURCE
#include "common.h"
#include "modules.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

void help_report(void)
{
    printf(
"Purpose:  Generate a metadata + analysis report for a file.\n"
"Syntax:   srl report <file> [--format txt|md|json|html] [-o OUT]\n"
"Args:\n"
"  <file>         input file\n"
"  --format FMT   output format (default txt)\n"
"  -o OUT         output path (default <file>.report.<ext>)\n"
"Includes:  file metadata, size, entropy, unique-byte count, classification.\n"
"Example:   srl report payload.bin --format json\n");
}

int cmd_report(int argc, char **argv)
{
    if (srl_wants_help(argc, argv) || argc < 1) { help_report(); return argc < 1; }

    const char *file = NULL, *fmt = "txt", *out = NULL;
    for (int i = 0; i < argc; i++) {
        if      (!strcmp(argv[i], "--format") && i+1 < argc) fmt = argv[++i];
        else if (!strcmp(argv[i], "-o")       && i+1 < argc) out = argv[++i];
        else if (argv[i][0] != '-') file = argv[i];
    }
    if (!file) { fprintf(stderr, "error: no input file\n"); return 1; }

    size_t n = 0;
    unsigned char *b = srl_read_file(file, &n);
    if (!b) { fprintf(stderr, "error: cannot read %s\n", file); return 1; }

    size_t freq[256]; srl_byte_freq(b, n, freq);
    size_t unique = 0; for (int i = 0; i < 256; i++) if (freq[i]) unique++;
    double h = srl_shannon_entropy(b, n);
    const char *name = srl_basename(file);

    char ts[32]; time_t now = time(NULL); struct tm tmv; localtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

    char defout[640];
    if (!out) { snprintf(defout, sizeof(defout), "%s.report.%s", file, fmt); out = defout; }

    FILE *f = fopen(out, "w");
    if (!f) { fprintf(stderr, "error: write %s\n", out); free(b); return 1; }

    if (!strcmp(fmt, "json")) {
        fprintf(f, "{\n  \"tool\": \"%s %s\",\n  \"file\": \"%s\",\n  \"generated\": \"%s\",\n"
                   "  \"size\": %zu,\n  \"entropy\": %.4f,\n  \"unique_bytes\": %zu\n}\n",
                SRL_NAME, SRL_VERSION, name, ts, n, h, unique);
    } else if (!strcmp(fmt, "md")) {
        fprintf(f, "# SRL Report: %s\n\n- Generated: %s\n- Size: %zu bytes\n"
                   "- Entropy: %.4f bits/byte\n- Unique bytes: %zu/256\n", name, ts, n, h, unique);
    } else if (!strcmp(fmt, "html")) {
        fprintf(f, "<!doctype html><meta charset=utf-8><title>SRL Report: %s</title>"
                   "<h1>SRL Report: %s</h1><ul>"
                   "<li>Generated: %s</li><li>Size: %zu bytes</li>"
                   "<li>Entropy: %.4f bits/byte</li><li>Unique bytes: %zu/256</li></ul>\n",
                name, name, ts, n, h, unique);
    } else { /* txt */
        fprintf(f, "%s %s - Report\n========================\n"
                   "File         : %s\nGenerated    : %s\nSize         : %zu bytes\n"
                   "Entropy      : %.4f bits/byte\nUnique bytes : %zu/256\n",
                SRL_NAME, SRL_VERSION, name, ts, n, h, unique);
    }
    fclose(f);
    printf("Report written: %s (%s)\n", out, fmt);

    free(b);
    return 0;
}
