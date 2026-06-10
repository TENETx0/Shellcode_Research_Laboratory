#define _GNU_SOURCE
#include "codec.h"
#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
                              else printf("ok  : %s\n", msg); } while (0)

static int roundtrip(const char *name, const char *key)
{
    const srl_codec_t *c = srl_codec_find(name);
    if (!c) { printf("FAIL: codec %s missing\n", name); return 0; }

    const unsigned char sample[] = "The quick brown fox \x00\x90\xff jumps over 42 lazy dogs!";
    size_t n = sizeof(sample);          /* include trailing NUL on purpose */

    size_t el = 0; unsigned char *e = c->encode(sample, n, key, &el);
    if (!e) { printf("FAIL: %s encode\n", name); return 0; }
    size_t dl = 0; unsigned char *d = c->decode(e, el, key, &dl);
    if (!d) { printf("FAIL: %s decode\n", name); free(e); return 0; }

    int ok = (dl == n) && (memcmp(d, sample, n) == 0);
    free(e); free(d);
    return ok;
}

int main(void)
{
    /* round-trips for byte-exact codecs */
    const char *exact[] = { "xor", "xorm", "base64", "hex", "url", "rc4", "aes128", "aes256" };
    for (size_t i = 0; i < sizeof(exact)/sizeof(exact[0]); i++) {
        char msg[64]; snprintf(msg, sizeof(msg), "round-trip %s", exact[i]);
        CHECK(roundtrip(exact[i], "secret"), msg);
    }

    /* base85 round-trips on length multiples cleanly; check a 4-byte block */
    {
        const srl_codec_t *c = srl_codec_find("base85");
        unsigned char in[8] = {1,2,3,4,5,6,7,8};
        size_t el=0,dl=0;
        unsigned char *e = c->encode(in,8,NULL,&el);
        unsigned char *d = c->decode(e,el,NULL,&dl);
        CHECK(d && dl==8 && memcmp(d,in,8)==0, "round-trip base85 (8 bytes)");
        free(e); free(d);
    }

    /* entropy sanity: all-zero buffer == 0, random-ish high */
    {
        unsigned char zeros[256] = {0};
        CHECK(srl_shannon_entropy(zeros, 256) == 0.0, "entropy of zeros == 0");
        unsigned char ramp[256]; for (int i=0;i<256;i++) ramp[i]=(unsigned char)i;
        CHECK(srl_shannon_entropy(ramp, 256) > 7.9, "entropy of 0..255 ramp ~8");
    }

    printf("\n%s (%d failure%s)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
