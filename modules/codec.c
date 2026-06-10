#define _GNU_SOURCE
#include "codec.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

/* ----------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------- */
static const char *keystr(const char *k) { return (k && *k) ? k : "srl"; }

/* ----------------------------------------------------------------------
 * Single-byte XOR (symmetric)
 * -------------------------------------------------------------------- */
static unsigned char *xor_run(const unsigned char *in, size_t n,
                              const char *key, size_t *out)
{
    unsigned char k = (unsigned char)keystr(key)[0];
    unsigned char *o = malloc(n ? n : 1);
    if (!o) return NULL;
    for (size_t i = 0; i < n; i++) o[i] = in[i] ^ k;
    *out = n;
    return o;
}

/* Multi-byte repeating XOR (symmetric) */
static unsigned char *xorm_run(const unsigned char *in, size_t n,
                               const char *key, size_t *out)
{
    const char *k = keystr(key);
    size_t kl = strlen(k);
    unsigned char *o = malloc(n ? n : 1);
    if (!o) return NULL;
    for (size_t i = 0; i < n; i++) o[i] = in[i] ^ (unsigned char)k[i % kl];
    *out = n;
    return o;
}

/* ----------------------------------------------------------------------
 * Base64
 * -------------------------------------------------------------------- */
static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static unsigned char *b64_enc(const unsigned char *in, size_t n,
                              const char *key, size_t *out)
{
    (void)key;
    size_t olen = 4 * ((n + 2) / 3);
    unsigned char *o = malloc(olen + 1);
    if (!o) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = in[i] << 16;
        if (i + 1 < n) v |= in[i+1] << 8;
        if (i + 2 < n) v |= in[i+2];
        o[j++] = B64[(v >> 18) & 0x3f];
        o[j++] = B64[(v >> 12) & 0x3f];
        o[j++] = (i + 1 < n) ? B64[(v >> 6) & 0x3f] : '=';
        o[j++] = (i + 2 < n) ? B64[v & 0x3f]        : '=';
    }
    o[j] = '\0';
    *out = j;
    return o;
}

static int b64_val(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static unsigned char *b64_dec(const unsigned char *in, size_t n,
                              const char *key, size_t *out)
{
    (void)key;
    unsigned char *o = malloc(n ? n : 1);
    if (!o) return NULL;
    size_t j = 0; int buf = 0, bits = 0;
    for (size_t i = 0; i < n; i++) {
        if (in[i] == '=' || isspace(in[i])) continue;
        int v = b64_val(in[i]);
        if (v < 0) { free(o); return NULL; }
        buf = (buf << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; o[j++] = (unsigned char)((buf >> bits) & 0xff); }
    }
    *out = j;
    return o;
}

/* ----------------------------------------------------------------------
 * Ascii85 (Adobe variant, no <~ ~> delimiters)
 * -------------------------------------------------------------------- */
static unsigned char *b85_enc(const unsigned char *in, size_t n,
                              const char *key, size_t *out)
{
    (void)key;
    unsigned char *o = malloc(n * 5 / 4 + 16);
    if (!o) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < n; i += 4) {
        uint32_t v = 0; int cnt = 0;
        for (int b = 0; b < 4; b++) { v <<= 8; if (i + (size_t)b < n) { v |= in[i+b]; cnt++; } }
        char tmp[5];
        for (int t = 4; t >= 0; t--) { tmp[t] = (char)('!' + v % 85); v /= 85; }
        for (int t = 0; t < cnt + 1; t++) o[j++] = (unsigned char)tmp[t];
    }
    o[j] = '\0';
    *out = j;
    return o;
}

static unsigned char *b85_dec(const unsigned char *in, size_t n,
                              const char *key, size_t *out)
{
    (void)key;
    unsigned char *o = malloc(n + 4);
    if (!o) return NULL;
    size_t j = 0; uint32_t tup = 0; int cnt = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = in[i];
        if (isspace(c)) continue;
        if (c < '!' || c > 'u') { free(o); return NULL; }
        tup = tup * 85 + (uint32_t)(c - '!');
        if (++cnt == 5) {
            for (int b = 3; b >= 0; b--) o[j++] = (unsigned char)((tup >> (b*8)) & 0xff);
            tup = 0; cnt = 0;
        }
    }
    if (cnt) {
        for (int k = cnt; k < 5; k++) tup = tup * 85 + 84;
        for (int b = 3; b >= 4 - (cnt - 1); b--) o[j++] = (unsigned char)((tup >> (b*8)) & 0xff);
    }
    *out = j;
    return o;
}

/* ----------------------------------------------------------------------
 * Hex
 * -------------------------------------------------------------------- */
static unsigned char *hex_enc(const unsigned char *in, size_t n,
                              const char *key, size_t *out)
{
    (void)key;
    unsigned char *o = malloc(n * 2 + 1);
    if (!o) return NULL;
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { o[i*2] = (unsigned char)h[in[i] >> 4]; o[i*2+1] = (unsigned char)h[in[i] & 0xf]; }
    o[n*2] = '\0';
    *out = n * 2;
    return o;
}

static int hv(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned char *hex_dec(const unsigned char *in, size_t n,
                              const char *key, size_t *out)
{
    (void)key;
    unsigned char *o = malloc(n / 2 + 1);
    if (!o) return NULL;
    size_t j = 0; int hi = -1;
    for (size_t i = 0; i < n; i++) {
        if (isspace(in[i])) continue;
        int v = hv(in[i]);
        if (v < 0) { free(o); return NULL; }
        if (hi < 0) hi = v;
        else { o[j++] = (unsigned char)((hi << 4) | v); hi = -1; }
    }
    *out = j;
    return o;
}

/* ----------------------------------------------------------------------
 * ROT13 (symmetric) and Caesar (keyed shift)
 * -------------------------------------------------------------------- */
static unsigned char *rot_enc(const unsigned char *in, size_t n,
                              const char *key, size_t *out)
{
    (void)key;
    unsigned char *o = malloc(n ? n : 1);
    if (!o) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = in[i];
        if (c >= 'a' && c <= 'z') c = (unsigned char)('a' + (c - 'a' + 13) % 26);
        else if (c >= 'A' && c <= 'Z') c = (unsigned char)('A' + (c - 'A' + 13) % 26);
        o[i] = c;
    }
    *out = n;
    return o;
}

static unsigned char *caesar_shift(const unsigned char *in, size_t n,
                                   const char *key, int dir, size_t *out)
{
    int s = atoi(keystr(key));
    if (s == 0) s = 3;
    s = ((s % 26) + 26) % 26;
    if (dir < 0) s = (26 - s) % 26;
    unsigned char *o = malloc(n ? n : 1);
    if (!o) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = in[i];
        if (c >= 'a' && c <= 'z') c = (unsigned char)('a' + (c - 'a' + s) % 26);
        else if (c >= 'A' && c <= 'Z') c = (unsigned char)('A' + (c - 'A' + s) % 26);
        o[i] = c;
    }
    *out = n;
    return o;
}
static unsigned char *caesar_enc(const unsigned char *i, size_t n, const char *k, size_t *o){ return caesar_shift(i,n,k,+1,o);}
static unsigned char *caesar_dec(const unsigned char *i, size_t n, const char *k, size_t *o){ return caesar_shift(i,n,k,-1,o);}

/* ----------------------------------------------------------------------
 * URL percent-encoding
 * -------------------------------------------------------------------- */
static int unreserved(unsigned char c)
{
    return isalnum(c) || c=='-' || c=='_' || c=='.' || c=='~';
}
static unsigned char *url_enc(const unsigned char *in, size_t n,
                              const char *key, size_t *out)
{
    (void)key;
    unsigned char *o = malloc(n * 3 + 1);
    if (!o) return NULL;
    size_t j = 0;
    static const char *h = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        if (unreserved(in[i])) o[j++] = in[i];
        else { o[j++] = '%'; o[j++] = (unsigned char)h[in[i]>>4]; o[j++] = (unsigned char)h[in[i]&0xf]; }
    }
    o[j] = '\0';
    *out = j;
    return o;
}
static unsigned char *url_dec(const unsigned char *in, size_t n,
                              const char *key, size_t *out)
{
    (void)key;
    unsigned char *o = malloc(n ? n : 1);
    if (!o) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        if (in[i] == '%' && i + 2 < n) {
            int a = hv(in[i+1]), b = hv(in[i+2]);
            if (a < 0 || b < 0) { free(o); return NULL; }
            o[j++] = (unsigned char)((a << 4) | b); i += 2;
        } else o[j++] = in[i];
    }
    *out = j;
    return o;
}

/* ----------------------------------------------------------------------
 * RC4 (symmetric stream cipher, classic reference implementation)
 * -------------------------------------------------------------------- */
static unsigned char *rc4_run(const unsigned char *in, size_t n,
                              const char *key, size_t *out)
{
    const char *k = keystr(key);
    size_t kl = strlen(k);
    unsigned char s[256];
    for (int i = 0; i < 256; i++) s[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + (unsigned char)k[i % kl]) & 0xff;
        unsigned char t = s[i]; s[i] = s[j]; s[j] = t;
    }
    unsigned char *o = malloc(n ? n : 1);
    if (!o) return NULL;
    int x = 0, y = 0;
    for (size_t c = 0; c < n; c++) {
        x = (x + 1) & 0xff;
        y = (y + s[x]) & 0xff;
        unsigned char t = s[x]; s[x] = s[y]; s[y] = t;
        o[c] = in[c] ^ s[(s[x] + s[y]) & 0xff];
    }
    *out = n;
    return o;
}

/* ----------------------------------------------------------------------
 * AES-CBC via OpenSSL EVP. IV (16 bytes) is randomly generated and
 * prepended to the ciphertext. Key derived from passphrase via SHA-256.
 * -------------------------------------------------------------------- */
static unsigned char *aes_enc(const unsigned char *in, size_t n,
                              const char *key, int bits, size_t *out)
{
    unsigned char dk[32]; SHA256((const unsigned char*)keystr(key), strlen(keystr(key)), dk);
    int klen = bits / 8;
    const EVP_CIPHER *c = (bits == 256) ? EVP_aes_256_cbc() : EVP_aes_128_cbc();

    unsigned char iv[16];
    if (RAND_bytes(iv, 16) != 1) return NULL;

    unsigned char *o = malloc(16 + n + 16); /* iv + ct + pad block */
    if (!o) return NULL;
    memcpy(o, iv, 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(o); return NULL; }
    int ol = 0, tmp = 0;
    if (EVP_EncryptInit_ex(ctx, c, NULL, dk, iv) != 1 ||
        EVP_CIPHER_CTX_set_key_length(ctx, klen) < 0 ||
        EVP_EncryptUpdate(ctx, o + 16, &ol, in, (int)n) != 1 ||
        EVP_EncryptFinal_ex(ctx, o + 16 + ol, &tmp) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(o); return NULL;
    }
    EVP_CIPHER_CTX_free(ctx);
    *out = 16 + (size_t)ol + (size_t)tmp;
    return o;
}

static unsigned char *aes_dec(const unsigned char *in, size_t n,
                              const char *key, int bits, size_t *out)
{
    if (n < 16) return NULL;
    unsigned char dk[32]; SHA256((const unsigned char*)keystr(key), strlen(keystr(key)), dk);
    const EVP_CIPHER *c = (bits == 256) ? EVP_aes_256_cbc() : EVP_aes_128_cbc();
    const unsigned char *iv = in;

    unsigned char *o = malloc(n);
    if (!o) return NULL;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(o); return NULL; }
    int ol = 0, tmp = 0;
    if (EVP_DecryptInit_ex(ctx, c, NULL, dk, iv) != 1 ||
        EVP_DecryptUpdate(ctx, o, &ol, in + 16, (int)(n - 16)) != 1 ||
        EVP_DecryptFinal_ex(ctx, o + ol, &tmp) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(o); return NULL;
    }
    EVP_CIPHER_CTX_free(ctx);
    *out = (size_t)ol + (size_t)tmp;
    return o;
}

static unsigned char *aes128_enc(const unsigned char*i,size_t n,const char*k,size_t*o){return aes_enc(i,n,k,128,o);}
static unsigned char *aes128_dec(const unsigned char*i,size_t n,const char*k,size_t*o){return aes_dec(i,n,k,128,o);}
static unsigned char *aes256_enc(const unsigned char*i,size_t n,const char*k,size_t*o){return aes_enc(i,n,k,256,o);}
static unsigned char *aes256_dec(const unsigned char*i,size_t n,const char*k,size_t*o){return aes_dec(i,n,k,256,o);}

/* ----------------------------------------------------------------------
 * Registry
 * -------------------------------------------------------------------- */
static const srl_codec_t TABLE[] = {
    { "xor",    xor_run,    xor_run,    1, "single-byte XOR" },
    { "xorm",   xorm_run,   xorm_run,   1, "multi-byte repeating XOR" },
    { "base64", b64_enc,    b64_dec,    0, "Base64" },
    { "base85", b85_enc,    b85_dec,    0, "Ascii85 / Base85" },
    { "hex",    hex_enc,    hex_dec,    0, "hexadecimal" },
    { "rot",    rot_enc,    rot_enc,    0, "ROT13" },
    { "caesar", caesar_enc, caesar_dec, 1, "Caesar shift cipher" },
    { "url",    url_enc,    url_dec,    0, "URL percent-encoding" },
    { "rc4",    rc4_run,    rc4_run,    1, "RC4 stream cipher" },
    { "aes128", aes128_enc, aes128_dec, 1, "AES-128-CBC" },
    { "aes256", aes256_enc, aes256_dec, 1, "AES-256-CBC" },
};

const srl_codec_t *srl_codec_find(const char *name)
{
    for (size_t i = 0; i < sizeof(TABLE)/sizeof(TABLE[0]); i++)
        if (!strcmp(TABLE[i].name, name)) return &TABLE[i];
    return NULL;
}

const srl_codec_t *srl_codec_all(size_t *count)
{
    *count = sizeof(TABLE)/sizeof(TABLE[0]);
    return TABLE;
}
