#define _GNU_SOURCE
#include "log.h"
#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int srl_verbose = 0;
int srl_debug   = 0;

static FILE          *g_log    = NULL;
static srl_loglevel_t g_level  = LL_INFO;

static const char *lvl_name(srl_loglevel_t l)
{
    switch (l) {
        case LL_ERROR: return "ERROR";
        case LL_WARN:  return "WARN";
        case LL_INFO:  return "INFO";
        case LL_DEBUG: return "DEBUG";
        default:       return "?";
    }
}

void srl_log_init(void)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/srl.log", srl_home_dir());
    g_log = fopen(path, "a");
    if (srl_debug)      g_level = LL_DEBUG;
    else if (srl_verbose) g_level = LL_INFO;
}

void srl_log_set_level(srl_loglevel_t l) { g_level = l; }

void srl_log(srl_loglevel_t lvl, const char *fmt, ...)
{
    if (lvl > g_level && !g_log) return;

    char ts[32];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

    va_list ap;
    if (g_log) {
        va_start(ap, fmt);
        fprintf(g_log, "[%s] %-5s ", ts, lvl_name(lvl));
        vfprintf(g_log, fmt, ap);
        fputc('\n', g_log);
        fflush(g_log);
        va_end(ap);
    }
    if (lvl <= g_level && (srl_verbose || srl_debug || lvl <= LL_WARN)) {
        va_start(ap, fmt);
        fprintf(stderr, "%-5s ", lvl_name(lvl));
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
        va_end(ap);
    }
}

void srl_log_close(void)
{
    if (g_log) { fclose(g_log); g_log = NULL; }
}
