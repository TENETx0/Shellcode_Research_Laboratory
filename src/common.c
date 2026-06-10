#define _GNU_SOURCE
#include "common.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

unsigned char *srl_read_file(const char *path, size_t *len)
{
    if (len) *len = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);

    unsigned char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }

    buf[got] = '\0'; /* convenience NUL for text callers */
    if (len) *len = got;
    return buf;
}

int srl_write_file(const char *path, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t wrote = fwrite(buf, 1, len, f);
    int rc = (wrote == len) ? 0 : -1;
    if (fclose(f) != 0) rc = -1;
    return rc;
}

double srl_shannon_entropy(const unsigned char *buf, size_t len)
{
    if (!buf || len == 0) return 0.0;
    size_t freq[256];
    srl_byte_freq(buf, len, freq);

    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / (double)len;
        h -= p * log2(p);
    }
    return h;
}

void srl_byte_freq(const unsigned char *buf, size_t len, size_t freq[256])
{
    memset(freq, 0, 256 * sizeof(size_t));
    for (size_t i = 0; i < len; i++) freq[buf[i]]++;
}

const char *srl_basename(const char *path)
{
    const char *b = strrchr(path, '/');
    return b ? b + 1 : path;
}

int srl_is_tty(FILE *f)
{
    return isatty(fileno(f));
}

void srl_hexdump(const unsigned char *buf, size_t len, size_t max)
{
    size_t n = (max && len > max) ? max : len;
    for (size_t off = 0; off < n; off += 16) {
        printf("%08zx  ", off);
        for (size_t i = 0; i < 16; i++) {
            if (off + i < n) printf("%02x ", buf[off + i]);
            else             printf("   ");
            if (i == 7) putchar(' ');
        }
        printf(" |");
        for (size_t i = 0; i < 16 && off + i < n; i++) {
            unsigned char c = buf[off + i];
            putchar((c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("|\n");
    }
    if (max && len > max)
        printf("... (%zu bytes total, truncated)\n", len);
}

double srl_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
