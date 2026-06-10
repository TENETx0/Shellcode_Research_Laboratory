#define _GNU_SOURCE
#include "common.h"
#include "codec.h"
#include "modules.h"

#include <stdlib.h>
#include <string.h>

void help_benchmark(void)
{
    printf(
"Purpose:  Compare every codec on one file: speed, size delta, entropy.\n"
"Syntax:   srl benchmark <file> [--iter N] [--key K]\n"
"Args:\n"
"  <file>    input file\n"
"  --iter N  encode/decode repetitions for timing (default 100)\n"
"  --key  K  key for keyed codecs\n"
"Output:    ranking table sorted by encode throughput.\n"
"Example:   srl benchmark payload.bin --iter 500\n");
}

typedef struct { const char *name; double enc_ms, dec_ms; size_t outsz; double ent; int ok; } row_t;

int cmd_benchmark(int argc, char **argv)
{
    if (srl_wants_help(argc, argv) || argc < 1) { help_benchmark(); return argc < 1; }

    const char *file = NULL, *key = NULL; long iter = 100;
    for (int i = 0; i < argc; i++) {
        if      (!strcmp(argv[i], "--iter") && i+1 < argc) iter = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--key")  && i+1 < argc) key  = argv[++i];
        else if (argv[i][0] != '-') file = argv[i];
    }
    if (!file) { fprintf(stderr, "error: no input file\n"); return 1; }
    if (iter < 1) iter = 1;

    size_t len = 0;
    unsigned char *buf = srl_read_file(file, &len);
    if (!buf) { fprintf(stderr, "error: cannot read %s\n", file); return 1; }

    size_t count; const srl_codec_t *t = srl_codec_all(&count);
    row_t *rows = calloc(count, sizeof(row_t));

    for (size_t i = 0; i < count; i++) {
        rows[i].name = t[i].name;
        size_t ol = 0; unsigned char *enc = NULL;

        double e0 = srl_now();
        for (long k = 0; k < iter; k++) {
            if (enc) free(enc);
            enc = t[i].encode(buf, len, key, &ol);
            if (!enc) break;
        }
        double e1 = srl_now();
        if (!enc) { rows[i].ok = 0; continue; }

        rows[i].outsz = ol;
        rows[i].ent   = srl_shannon_entropy(enc, ol);
        rows[i].enc_ms = (e1 - e0) * 1000.0 / (double)iter;

        double d0 = srl_now();
        for (long k = 0; k < iter; k++) {
            size_t dl = 0; unsigned char *dec = t[i].decode(enc, ol, key, &dl);
            if (dec) free(dec);
        }
        double d1 = srl_now();
        rows[i].dec_ms = (d1 - d0) * 1000.0 / (double)iter;
        rows[i].ok = 1;
        free(enc);
    }

    /* sort by encode time ascending */
    for (size_t i = 0; i < count; i++)
        for (size_t j = i + 1; j < count; j++)
            if (rows[j].ok && (!rows[i].ok || rows[j].enc_ms < rows[i].enc_ms)) {
                row_t tmp = rows[i]; rows[i] = rows[j]; rows[j] = tmp;
            }

    printf("Benchmark on %s (%zu bytes, %ld iterations)\n\n", srl_basename(file), len, iter);
    printf("%-4s %-8s %10s %10s %10s %8s\n", "#", "codec", "enc(ms)", "dec(ms)", "out(B)", "entropy");
    printf("------------------------------------------------------------\n");
    int rank = 1;
    for (size_t i = 0; i < count; i++) {
        if (!rows[i].ok) { printf("  -  %-8s %10s %10s %10s %8s\n", rows[i].name, "FAIL","-","-","-"); continue; }
        printf("%-4d %-8s %10.4f %10.4f %10zu %8.3f\n",
               rank++, rows[i].name, rows[i].enc_ms, rows[i].dec_ms, rows[i].outsz, rows[i].ent);
    }

    free(rows);
    free(buf);
    return 0;
}
