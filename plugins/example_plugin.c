/* example_plugin.c
 *
 * Minimal SRL plugin. Build with:
 *   gcc -shared -fPIC -I../include example_plugin.c -o hello.so
 * Then:
 *   cp hello.so ~/.srl/plugins/
 *   srl plugin run hello somefile.bin
 */
#include "plugin.h"
#include <stdio.h>

static int hello_exec(srl_plugin_ctx_t *ctx)
{
    printf("[hello plugin] ABI=%d\n", ctx->abi);
    if (ctx->input_path)
        printf("[hello plugin] file: %s (%zu bytes)\n", ctx->input_path, ctx->data_len);
    else
        printf("[hello plugin] no file supplied\n");

    if (ctx->data && ctx->data_len) {
        printf("[hello plugin] first byte: 0x%02x\n", ctx->data[0]);
    }
    return 0;
}

srl_plugin_t srl_plugin = {
    .name        = "hello",
    .version     = "1.0",
    .description = "example plugin: prints file metadata",
    .abi         = SRL_PLUGIN_ABI,
    .execute     = hello_exec,
};
