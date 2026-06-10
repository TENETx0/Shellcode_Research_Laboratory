#define _GNU_SOURCE
#include "common.h"
#include "config.h"
#include "log.h"
#include "modules.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*cmd_fn)(int, char **);
typedef void (*help_fn)(void);

typedef struct {
    const char *verb;
    cmd_fn      run;
    help_fn     help;
    const char *summary;
} entry_t;

static const entry_t COMMANDS[] = {
    { "encode",    cmd_encode,    help_encode,    "encode/transform a payload through codecs" },
    { "decode",    cmd_decode,    help_decode,    "reverse a codec chain or auto-detect layers" },
    { "entropy",   cmd_entropy,   help_entropy,   "measure randomness and byte statistics" },
    { "inspect",   cmd_inspect,   help_inspect,   "identify format and dump structure" },
    { "analyze",   cmd_analyze,   help_analyze,   "heuristic shellcode profiling" },
    { "benchmark", cmd_benchmark, help_benchmark, "compare codecs by speed/size/entropy" },
    { "visualize", cmd_visualize, help_visualize, "interactive ncurses viewer" },
    { "report",    cmd_report,    help_report,    "generate txt/md/json/html report" },
    { "plugin",    cmd_plugin,    help_plugin,    "manage and run dynamic plugins" },
};
static const size_t NCMD = sizeof(COMMANDS) / sizeof(COMMANDS[0]);

int srl_wants_help(int argc, char **argv)
{
    for (int i = 0; i < argc; i++)
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) return 1;
    return 0;
}

static void banner(void)
{
    const char *c = srl_is_tty(stdout) ? C_CYN : "";
    const char *r = srl_is_tty(stdout) ? C_RESET : "";
    printf("%s", c);
    printf("     ____  ____  _\n");
    printf("    / ___||  _ \\| |       %s%s%s\n", r, SRL_NAME, c);
    printf("    \\___ \\| |_) | |       %sv%s  -  research & analysis framework%s\n", r, SRL_VERSION, c);
    printf("     ___) |  _ <| |___    %sAuthor : %s%s\n", r, SRL_AUTHOR, c);
    printf("    |____/|_| \\_\\_____|   %sGitHub : %s%s\n", r, SRL_URL, c);
    printf("%s\n", r);
}

static void usage(void)
{
    banner();
    printf("\nUsage: srl <command> [args]  |  srl  (interactive)\n\n");
    printf("Commands:\n");
    for (size_t i = 0; i < NCMD; i++)
        printf("  %-10s %s\n", COMMANDS[i].verb, COMMANDS[i].summary);
    printf("\nGlobal flags: -h/--help  --verbose  --debug\n");
    printf("Run 'srl <command> --help' for detailed help.\n");
}

static const entry_t *find(const char *verb)
{
    for (size_t i = 0; i < NCMD; i++)
        if (!strcmp(COMMANDS[i].verb, verb)) return &COMMANDS[i];
    return NULL;
}

int srl_interactive(void)
{
    banner();
    char line[256];
    for (;;) {
        printf("\n1.Encode 2.Decode 3.Analyze 4.Entropy 5.Inspect "
               "6.Benchmark 7.Plugins 8.Report 9.Exit\nselection> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        int sel = atoi(line);
        if (sel == 9) break;

        char path[256] = {0};
        if (sel >= 1 && sel <= 6 && sel != 0) {
            printf("file path> "); fflush(stdout);
            if (!fgets(path, sizeof(path), stdin)) break;
            path[strcspn(path, "\n")] = '\0';
        }
        char *args[2] = { path, NULL };
        int ac = path[0] ? 1 : 0;

        switch (sel) {
            case 1: cmd_encode(ac, args);    break;
            case 2: cmd_decode(ac, args);    break;
            case 3: cmd_analyze(ac, args);   break;
            case 4: cmd_entropy(ac, args);   break;
            case 5: cmd_inspect(ac, args);   break;
            case 6: cmd_benchmark(ac, args); break;
            case 7: { char *p[1] = { (char*)"list" }; cmd_plugin(1, p); break; }
            case 8: cmd_report(ac, args);    break;
            default: printf("invalid selection\n");
        }
    }
    printf("bye.\n");
    return 0;
}

int main(int argc, char **argv)
{
    srl_config_t cfg;
    srl_config_load(&cfg);

    /* strip global flags, collect remaining */
    char *rest[64]; int rc_argc = 0;
    for (int i = 1; i < argc && rc_argc < 63; i++) {
        if      (!strcmp(argv[i], "--verbose")) srl_verbose = 1;
        else if (!strcmp(argv[i], "--debug"))   srl_debug = 1;
        else rest[rc_argc++] = argv[i];
    }
    rest[rc_argc] = NULL;

    srl_log_init();
    srl_log(LL_DEBUG, "start argc=%d", argc);

    int ret = 0;
    if (rc_argc == 0) {
        ret = srl_interactive();
    } else if (!strcmp(rest[0], "-h") || !strcmp(rest[0], "--help") || !strcmp(rest[0], "help")) {
        usage();
    } else {
        const entry_t *e = find(rest[0]);
        if (!e) { fprintf(stderr, "unknown command '%s'\n\n", rest[0]); usage(); ret = 1; }
        else    ret = e->run(rc_argc - 1, rest + 1);
    }

    srl_log(LL_DEBUG, "exit %d", ret);
    srl_log_close();
    return ret;
}
