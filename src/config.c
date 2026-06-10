#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

const char *srl_home_dir(void)
{
    static char dir[512];
    if (dir[0]) return dir;

    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(dir, sizeof(dir), "%s/.srl", home);
    mkdir(dir, 0700); /* ignore EEXIST */
    return dir;
}

static void set_defaults(srl_config_t *cfg)
{
    snprintf(cfg->output_path, sizeof(cfg->output_path), ".");
    snprintf(cfg->theme, sizeof(cfg->theme), "dark");
    snprintf(cfg->log_level, sizeof(cfg->log_level), "info");
    snprintf(cfg->report_format, sizeof(cfg->report_format), "txt");
}

static void trim(char *s)
{
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == '\r' ||
                 s[n-1] == ' '  || s[n-1] == '\t')) s[--n] = '\0';
}

void srl_config_load(srl_config_t *cfg)
{
    set_defaults(cfg);

    char path[600];
    snprintf(path, sizeof(path), "%s/config.ini", srl_home_dir());

    FILE *f = fopen(path, "r");
    if (!f) {
        /* write defaults so the user can edit them */
        f = fopen(path, "w");
        if (f) {
            fprintf(f,
                "; Shellcode Research Laboratory configuration\n"
                "output_path=%s\n"
                "theme=%s\n"
                "log_level=%s\n"
                "report_format=%s\n",
                cfg->output_path, cfg->theme,
                cfg->log_level, cfg->report_format);
            fclose(f);
        }
        return;
    }

    char line[640];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == ';' || line[0] == '#' || line[0] == '\n') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line, *val = eq + 1;
        trim(key); trim(val);
        if      (!strcmp(key, "output_path"))   snprintf(cfg->output_path,   sizeof(cfg->output_path),   "%s", val);
        else if (!strcmp(key, "theme"))         snprintf(cfg->theme,         sizeof(cfg->theme),         "%s", val);
        else if (!strcmp(key, "log_level"))     snprintf(cfg->log_level,     sizeof(cfg->log_level),     "%s", val);
        else if (!strcmp(key, "report_format")) snprintf(cfg->report_format, sizeof(cfg->report_format), "%s", val);
    }
    fclose(f);
}
