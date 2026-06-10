#define _GNU_SOURCE
#include "common.h"
#include "codec.h"
#include "modules.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

void help_encode(void)
{
    size_t n; const srl_codec_t *t = srl_codec_all(&n);
    printf(
"Purpose:  Encode/transform a binary payload through one or more codecs.\n"
"Syntax:   srl encode <file> [--chain a,b,c] [--algo NAME] [--key K] [-o OUT]\n"
"Args:\n"
"  <file>        input file (raw bytes)\n"
"  --algo NAME   single codec (default: xor)\n"
"  --chain LIST  comma-separated codec order, applied left to right\n"
"  --key  K      key for keyed codecs (xor, xorm, caesar, rc4, aes*)\n"
"  -o OUT        output path (default: <file>.enc)\n"
"Examples:\n"
"  srl encode payload.bin --algo base64\n"
"  srl encode payload.bin --chain xor,aes256,base64 --key s3cr3t\n"
"Supported codecs:\n");
    for (size_t i = 0; i < n; i++)
        printf("  %-8s %s%s\n", t[i].name, t[i].desc, t[i].keyed ? " [keyed]" : "");
    printf(
"Output: reports original size, encoded size, entropy before/after and time.\n");
}

static char **split_csv(const char *s, int *count)
{
    char *dup = strdup(s);
    if (!dup) { *count = 0; return NULL; }
    int cap = 8, n = 0;
    char **arr = malloc(cap * sizeof(char*));
    char *save = NULL, *tok = strtok_r(dup, ",", &save);
    while (tok) {
        if (n == cap) { cap *= 2; arr = realloc(arr, cap * sizeof(char*)); }
        arr[n++] = strdup(tok);
        tok = strtok_r(NULL, ",", &save);
    }
    free(dup);
    *count = n;
    return arr;
}

int cmd_encode(int argc, char **argv)
{
    if (srl_wants_help(argc, argv) || argc < 1) { help_encode(); return argc < 1; }

    const char *file = NULL, *out = NULL, *key = NULL, *chain = "xor";
    for (int i = 0; i < argc; i++) {
        if      (!strcmp(argv[i], "--chain") && i+1 < argc) chain = argv[++i];
        else if (!strcmp(argv[i], "--algo")  && i+1 < argc) chain = argv[++i];
        else if (!strcmp(argv[i], "--key")   && i+1 < argc) key   = argv[++i];
        else if (!strcmp(argv[i], "-o")      && i+1 < argc) out   = argv[++i];
        else if (argv[i][0] != '-')                         file  = argv[i];
    }
    if (!file) { fprintf(stderr, "error: no input file\n"); return 1; }

    size_t len = 0;
    unsigned char *buf = srl_read_file(file, &len);
    if (!buf) { fprintf(stderr, "error: cannot read %s\n", file); return 1; }

    int steps = 0;
    char **algos = split_csv(chain, &steps);
    double ent_before = srl_shannon_entropy(buf, len);
    size_t orig = len;

    double t0 = srl_now();
    unsigned char *cur = buf; size_t cur_len = len;
    for (int i = 0; i < steps; i++) {
        const srl_codec_t *c = srl_codec_find(algos[i]);
        if (!c) { fprintf(stderr, "error: unknown codec '%s'\n", algos[i]); free(cur); goto fail; }
        size_t nl = 0;
        unsigned char *nx = c->encode(cur, cur_len, key, &nl);
        if (!nx) { fprintf(stderr, "error: codec '%s' failed\n", algos[i]); free(cur); goto fail; }
        free(cur); cur = nx; cur_len = nl;
        srl_log(LL_INFO, "encode step %s: %zu -> %zu bytes", algos[i], len, nl);
    }
    double t1 = srl_now();

    char defout[600];
    if (!out) { snprintf(defout, sizeof(defout), "%s.enc", file); out = defout; }
    if (srl_write_file(out, cur, cur_len) != 0) { fprintf(stderr, "error: write %s\n", out); free(cur); goto fail; }

    double ent_after = srl_shannon_entropy(cur, cur_len);
    printf("Chain          : %s\n", chain);
    printf("Original Size  : %zu bytes\n", orig);
    printf("Encoded Size   : %zu bytes\n", cur_len);
    printf("Entropy Before : %.4f bits/byte\n", ent_before);
    printf("Entropy After  : %.4f bits/byte\n", ent_after);
    printf("Execution Time : %.3f ms\n", (t1 - t0) * 1000.0);
    printf("Output         : %s\n", out);

    free(cur);
    for (int i = 0; i < steps; i++) free(algos[i]);
    free(algos);
    return 0;

fail:
    for (int i = 0; i < steps; i++) free(algos[i]);
    free(algos);
    return 1;
}
