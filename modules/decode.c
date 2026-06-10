#define _GNU_SOURCE
#include "common.h"
#include "codec.h"
#include "modules.h"
#include "log.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

void help_decode(void)
{
    printf(
"Purpose:  Reverse a codec chain, or attempt automatic detection.\n"
"Syntax:   srl decode <file> [--chain a,b,c] [--key K] [-o OUT]\n"
"Args:\n"
"  <file>        encoded input file\n"
"  --chain LIST  codecs IN ENCODE ORDER; decode applies them in reverse\n"
"  --key  K      key for keyed codecs\n"
"  -o OUT        output path (default: <file>.dec)\n"
"Notes:\n"
"  When --chain is omitted, a heuristic layer detector inspects the bytes\n"
"  and peels recognisable text encodings (hex, base64, url) automatically.\n"
"  Keyed/binary ciphers (xor, rc4, aes) cannot be auto-detected and must be\n"
"  supplied via --chain with the correct --key.\n"
"Examples:\n"
"  srl decode payload.enc --chain xor,aes256,base64 --key s3cr3t\n"
"  srl decode payload.enc            # auto-detect text layers\n");
}

/* crude classifier for the outermost text layer */
static const char *detect_layer(const unsigned char *b, size_t n)
{
    if (n == 0) return NULL;
    int hexish = 1, b64ish = 1, urlish = 0;
    for (size_t i = 0; i < n && i < 4096; i++) {
        unsigned char c = b[i];
        if (!(isxdigit(c) || isspace(c))) hexish = 0;
        if (!(isalnum(c) || c=='+' || c=='/' || c=='=' || isspace(c))) b64ish = 0;
        if (c == '%') urlish = 1;
    }
    if (hexish && (n % 2 == 0 || n > 1)) return "hex";
    if (b64ish && n >= 4)               return "base64";
    if (urlish)                          return "url";
    return NULL;
}

static char **split_csv(const char *s, int *count)
{
    char *dup = strdup(s); if (!dup) { *count = 0; return NULL; }
    int cap = 8, n = 0; char **arr = malloc(cap * sizeof(char*));
    char *save = NULL, *tok = strtok_r(dup, ",", &save);
    while (tok) {
        if (n == cap) { cap *= 2; arr = realloc(arr, cap*sizeof(char*)); }
        arr[n++] = strdup(tok); tok = strtok_r(NULL, ",", &save);
    }
    free(dup); *count = n; return arr;
}

int cmd_decode(int argc, char **argv)
{
    if (srl_wants_help(argc, argv) || argc < 1) { help_decode(); return argc < 1; }

    const char *file = NULL, *out = NULL, *key = NULL, *chain = NULL;
    for (int i = 0; i < argc; i++) {
        if      (!strcmp(argv[i], "--chain") && i+1 < argc) chain = argv[++i];
        else if (!strcmp(argv[i], "--key")   && i+1 < argc) key   = argv[++i];
        else if (!strcmp(argv[i], "-o")      && i+1 < argc) out   = argv[++i];
        else if (argv[i][0] != '-')                         file  = argv[i];
    }
    if (!file) { fprintf(stderr, "error: no input file\n"); return 1; }

    size_t len = 0;
    unsigned char *cur = srl_read_file(file, &len);
    if (!cur) { fprintf(stderr, "error: cannot read %s\n", file); return 1; }
    size_t cur_len = len;

    printf("Detected/applied layers:\n");
    int idx = 1;

    if (chain) {
        int steps = 0; char **algos = split_csv(chain, &steps);
        for (int i = steps - 1; i >= 0; i--) {       /* reverse order */
            const srl_codec_t *c = srl_codec_find(algos[i]);
            if (!c) { fprintf(stderr, "error: unknown codec '%s'\n", algos[i]); free(cur); for(int k=0;k<steps;k++)free(algos[k]); free(algos); return 1; }
            size_t nl = 0; unsigned char *nx = c->decode(cur, cur_len, key, &nl);
            if (!nx) { fprintf(stderr, "error: layer '%s' failed to decode\n", algos[i]); free(cur); for(int k=0;k<steps;k++)free(algos[k]); free(algos); return 1; }
            free(cur); cur = nx; cur_len = nl;
            printf("  %d. %s\n", idx++, algos[i]);
        }
        for (int k = 0; k < steps; k++) free(algos[k]);
        free(algos);
    } else {
        const char *layer;
        int peeled = 0;
        while ((layer = detect_layer(cur, cur_len)) && peeled < 8) {
            const srl_codec_t *c = srl_codec_find(layer);
            size_t nl = 0; unsigned char *nx = c->decode(cur, cur_len, NULL, &nl);
            if (!nx || nl == 0 || nl >= cur_len) { if (nx) free(nx); break; }
            free(cur); cur = nx; cur_len = nl;
            printf("  %d. %s\n", idx++, layer);
            peeled++;
        }
        if (peeled == 0) printf("  (no text layers recognised; supply --chain)\n");
    }

    char defout[600];
    if (!out) { snprintf(defout, sizeof(defout), "%s.dec", file); out = defout; }
    if (srl_write_file(out, cur, cur_len) != 0) { fprintf(stderr, "error: write %s\n", out); free(cur); return 1; }

    printf("Successfully decoded -> %s (%zu bytes)\n", out, cur_len);
    free(cur);
    return 0;
}
