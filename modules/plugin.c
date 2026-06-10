#define _GNU_SOURCE
#include "common.h"
#include "config.h"
#include "modules.h"
#include "plugin.h"
#include "log.h"

#include <dirent.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

void help_plugin(void)
{
    printf(
"Purpose:  Manage and run dynamically loaded SRL plugins.\n"
"Syntax:   srl plugin <list|run NAME [file]|info PATH>\n"
"Sub-commands:\n"
"  list             list .so plugins in ~/.srl/plugins\n"
"  run NAME [file]  load ~/.srl/plugins/NAME.so and execute it\n"
"  info PATH        load PATH and print its metadata\n"
"Plugin contract: export a symbol 'srl_plugin' of type srl_plugin_t whose\n"
".abi == SRL_PLUGIN_ABI. See plugins/example_plugin.c and docs.\n"
"Example:  srl plugin run hello payload.bin\n");
}

static const char *plugin_dir(void)
{
    static char dir[600];
    snprintf(dir, sizeof(dir), "%s/plugins", srl_home_dir());
    mkdir(dir, 0700);
    return dir;
}

static srl_plugin_t *load(const char *path, void **handle)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "error: dlopen: %s\n", dlerror()); return NULL; }
    dlerror();
    srl_plugin_t *p = (srl_plugin_t *)dlsym(h, "srl_plugin");
    const char *err = dlerror();
    if (err || !p) { fprintf(stderr, "error: dlsym 'srl_plugin': %s\n", err ? err : "missing"); dlclose(h); return NULL; }
    if (p->abi != SRL_PLUGIN_ABI) {
        fprintf(stderr, "error: plugin ABI %d != %d\n", p->abi, SRL_PLUGIN_ABI);
        dlclose(h); return NULL;
    }
    *handle = h;
    return p;
}

static int do_list(void)
{
    const char *dir = plugin_dir();
    DIR *d = opendir(dir);
    if (!d) { printf("(no plugins; create %s)\n", dir); return 0; }
    struct dirent *e; int found = 0;
    printf("Plugins in %s:\n", dir);
    while ((e = readdir(d))) {
        size_t l = strlen(e->d_name);
        if (l > 3 && !strcmp(e->d_name + l - 3, ".so")) {
            char path[1200]; snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
            void *h = NULL; srl_plugin_t *p = load(path, &h);
            if (p) { printf("  %-20s v%-6s %s\n", p->name, p->version, p->description); dlclose(h); found++; }
        }
    }
    closedir(d);
    if (!found) printf("  (none)\n");
    return 0;
}

static int do_run(const char *name, const char *file)
{
    char path[1200];
    if (strchr(name, '/')) snprintf(path, sizeof(path), "%s", name);
    else                   snprintf(path, sizeof(path), "%s/%s.so", plugin_dir(), name);

    void *h = NULL; srl_plugin_t *p = load(path, &h);
    if (!p) return 1;

    srl_plugin_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.abi = SRL_PLUGIN_ABI;
    ctx.input_path = file;
    if (file) ctx.data = srl_read_file(file, &ctx.data_len);

    srl_log(LL_INFO, "running plugin %s", p->name);
    int rc = p->execute ? p->execute(&ctx) : -1;

    free(ctx.data);
    dlclose(h);
    return rc;
}

int cmd_plugin(int argc, char **argv)
{
    if (srl_wants_help(argc, argv) || argc < 1) { help_plugin(); return argc < 1; }

    if (!strcmp(argv[0], "list")) return do_list();
    if (!strcmp(argv[0], "run") && argc >= 2)  return do_run(argv[1], argc >= 3 ? argv[2] : NULL);
    if (!strcmp(argv[0], "info") && argc >= 2) {
        void *h = NULL; srl_plugin_t *p = load(argv[1], &h);
        if (!p) return 1;
        printf("Name        : %s\nVersion     : %s\nABI         : %d\nDescription : %s\n",
               p->name, p->version, p->abi, p->description);
        dlclose(h);
        return 0;
    }
    /* install/remove/enable/disable map to filesystem ops in ~/.srl/plugins */
    if (!strcmp(argv[0], "install") && argc >= 2) {
        printf("Copy your built .so into %s to install it.\n", plugin_dir());
        return 0;
    }
    help_plugin();
    return 1;
}
