#ifndef _MASH_JOBS_H
#define _MASH_JOBS_H

#include "mash.h"

#define JOBS_COMMAND_LEN 128

void jobs_build_command(int argc, char* argv[], char* out, int out_size);
void jobs_set_shell_pgid(int pgid);
void jobs_add(int pid, int pgid, const char* command);
void jobs_reap_background(void);
int jobs_builtin(int argc, char* argv[]);
int jobs_fg_builtin(int argc, char* argv[]);
int jobs_bg_builtin(int argc, char* argv[]);

#endif
