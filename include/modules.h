#ifndef SRL_MODULES_H
#define SRL_MODULES_H

/* Each command follows the same signature: it receives argv starting at the
 * sub-command's own arguments (i.e. argv[0] == first arg after the verb). */

int cmd_encode(int argc, char **argv);
int cmd_decode(int argc, char **argv);
int cmd_entropy(int argc, char **argv);
int cmd_inspect(int argc, char **argv);
int cmd_analyze(int argc, char **argv);
int cmd_benchmark(int argc, char **argv);
int cmd_visualize(int argc, char **argv);
int cmd_report(int argc, char **argv);
int cmd_plugin(int argc, char **argv);

/* Help printers (used by both -h and the dispatcher). */
void help_encode(void);
void help_decode(void);
void help_entropy(void);
void help_inspect(void);
void help_analyze(void);
void help_benchmark(void);
void help_visualize(void);
void help_report(void);
void help_plugin(void);

/* Interactive REPL. */
int srl_interactive(void);

/* True if argv contains -h/--help. */
int srl_wants_help(int argc, char **argv);

#endif /* SRL_MODULES_H */
