#ifndef SRL_PLUGIN_H
#define SRL_PLUGIN_H

#include <stddef.h>

#define SRL_PLUGIN_ABI 1

/* Context passed to a plugin's execute() function. Kept deliberately small
 * and append-only so plugins compiled against older headers keep working. */
typedef struct {
    int            abi;        /* must equal SRL_PLUGIN_ABI            */
    const char    *input_path; /* file the user passed, may be NULL    */
    unsigned char *data;       /* file contents, may be NULL           */
    size_t         data_len;
    int            argc;
    char         **argv;
} srl_plugin_ctx_t;

/* The structure every plugin must export via a symbol named "srl_plugin". */
typedef struct {
    char name[64];
    char version[16];
    char description[128];
    int  abi;                                  /* SRL_PLUGIN_ABI */
    int  (*execute)(srl_plugin_ctx_t *ctx);
} srl_plugin_t;

#endif /* SRL_PLUGIN_H */
