#ifndef SRL_LOG_H
#define SRL_LOG_H

typedef enum { LL_ERROR = 0, LL_WARN, LL_INFO, LL_DEBUG } srl_loglevel_t;

void srl_log_init(void);                 /* opens ~/.srl/srl.log              */
void srl_log_set_level(srl_loglevel_t l);/* runtime threshold                 */
void srl_log(srl_loglevel_t lvl, const char *fmt, ...);
void srl_log_close(void);

/* set by --verbose / --debug parsing in main */
extern int srl_verbose;
extern int srl_debug;

#endif /* SRL_LOG_H */
