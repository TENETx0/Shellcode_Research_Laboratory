#ifndef SRL_COMMON_H
#define SRL_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define SRL_NAME    "Shellcode Research Laboratory"
#define SRL_VERSION "1.0"
#define SRL_AUTHOR  "TENETx0"
#define SRL_URL     "https://github.com/TENETx0/Shellcode_Research_Laboratory"

/* ANSI colours (disabled automatically when not a TTY in printing helpers) */
#define C_RESET "\033[0m"
#define C_BOLD  "\033[1m"
#define C_RED   "\033[31m"
#define C_GRN   "\033[32m"
#define C_YEL   "\033[33m"
#define C_CYN   "\033[36m"

/* ---- File helpers ---------------------------------------------------- */
/* Reads an entire file into a heap buffer. Caller frees. Returns NULL on
 * error and sets *len = 0. */
unsigned char *srl_read_file(const char *path, size_t *len);

/* Writes buffer to path. Returns 0 on success, -1 on error. */
int srl_write_file(const char *path, const unsigned char *buf, size_t len);

/* ---- Analysis helpers ------------------------------------------------ */
/* Shannon entropy in bits/byte over [0,8]. */
double srl_shannon_entropy(const unsigned char *buf, size_t len);

/* Fills freq[256] with byte counts. */
void srl_byte_freq(const unsigned char *buf, size_t len, size_t freq[256]);

/* ---- Misc ------------------------------------------------------------ */
const char *srl_basename(const char *path);
int  srl_is_tty(FILE *f);
void srl_hexdump(const unsigned char *buf, size_t len, size_t max);

/* monotonic time in seconds (double) */
double srl_now(void);

#endif /* SRL_COMMON_H */
