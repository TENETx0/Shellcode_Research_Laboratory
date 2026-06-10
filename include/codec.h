#ifndef SRL_CODEC_H
#define SRL_CODEC_H

#include <stddef.h>

/* Generic codec interface. Each codec takes an input buffer and returns a
 * freshly allocated output buffer (caller frees). Returns NULL on error.
 * The optional key string is used by keyed codecs (xor, rc4, aes, caesar). */

typedef unsigned char *(*srl_codec_fn)(const unsigned char *in, size_t in_len,
                                       const char *key, size_t *out_len);

typedef struct {
    const char  *name;     /* lowercase identifier used on the CLI   */
    srl_codec_fn encode;
    srl_codec_fn decode;
    int          keyed;    /* 1 if a key is required                 */
    const char  *desc;
} srl_codec_t;

/* Lookup a codec by name, NULL if unknown. */
const srl_codec_t *srl_codec_find(const char *name);

/* Iterate registered codecs (for --list and benchmark). */
const srl_codec_t *srl_codec_all(size_t *count);

#endif /* SRL_CODEC_H */
