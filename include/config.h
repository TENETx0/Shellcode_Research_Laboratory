#ifndef SRL_CONFIG_H
#define SRL_CONFIG_H

typedef struct {
    char output_path[512];   /* default output dir/file prefix */
    char theme[32];          /* "dark" / "light" / "mono"      */
    char log_level[16];      /* error/warn/info/debug          */
    char report_format[16];  /* txt/html/md/json               */
} srl_config_t;

/* Loads ~/.srl/config.ini, creating defaults if absent. */
void srl_config_load(srl_config_t *cfg);

/* Returns the expanded ~/.srl directory, creating it if needed. */
const char *srl_home_dir(void);

#endif /* SRL_CONFIG_H */
