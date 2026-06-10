#define _GNU_SOURCE
#include "common.h"
#include "modules.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

void help_entropy(void)
{
    printf(
"Purpose:  Measure randomness and byte statistics of a file.\n"
"Syntax:   srl entropy <file>\n"
"Args:\n"
"  <file>   input file\n"
"Output:   Shannon entropy (bits/byte), classification, compression ratio,\n"
"          unique-byte count and an ASCII distribution histogram.\n"
"Example:  srl entropy payload.bin\n");
}

static const char *classify(double h)
{
    if (h < 4.0) return "Low (structured / text-like)";
    if (h < 7.0) return "Medium (mixed / lightly encoded)";
    if (h < 7.8) return "High (compressed / encoded)";
    return "Very High (encrypted / random)";
}

int cmd_entropy(int argc, char **argv)
{
    if (srl_wants_help(argc, argv) || argc < 1) { help_entropy(); return argc < 1; }

    const char *file = argv[0];
    size_t len = 0;
    unsigned char *buf = srl_read_file(file, &len);
    if (!buf) { fprintf(stderr, "error: cannot read %s\n", file); return 1; }
    if (len == 0) { printf("file is empty\n"); free(buf); return 0; }

    size_t freq[256];
    srl_byte_freq(buf, len, freq);
    double h = srl_shannon_entropy(buf, len);

    size_t unique = 0;
    for (int i = 0; i < 256; i++) if (freq[i]) unique++;

    /* compression ratio via zlib as an empirical randomness proxy */
    uLongf clen = compressBound((uLong)len);
    unsigned char *cbuf = malloc(clen);
    double ratio = 0.0;
    if (cbuf && compress2(cbuf, &clen, buf, (uLong)len, 9) == Z_OK)
        ratio = (double)clen / (double)len;
    free(cbuf);

    printf("File           : %s\n", srl_basename(file));
    printf("Size           : %zu bytes\n", len);
    printf("Entropy Score  : %.4f / 8.0 bits/byte\n", h);
    printf("Classification : %s\n", classify(h));
    printf("Unique Bytes   : %zu / 256\n", unique);
    printf("Compression    : %.3f (compressed/original; ~1.0 => random)\n", ratio);

    /* 16-bucket histogram */
    size_t bucket[16] = {0}, maxb = 1;
    for (int i = 0; i < 256; i++) bucket[i / 16] += freq[i];
    for (int i = 0; i < 16; i++) if (bucket[i] > maxb) maxb = bucket[i];

    printf("\nByte Distribution (16 buckets of 16 byte-values):\n");
    for (int i = 0; i < 16; i++) {
        int bars = (int)((bucket[i] * 40) / maxb);
        printf("  %02x-%02x |", i*16, i*16+15);
        for (int b = 0; b < bars; b++) putchar('#');
        printf(" %zu\n", bucket[i]);
    }

    free(buf);
    return 0;
}
