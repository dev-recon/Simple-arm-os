#ifndef ARMOS_BSDINSTALL_UTIL_H
#define ARMOS_BSDINSTALL_UTIL_H

#include <sys/types.h>

void setprogname(const char *name);
const char *getprogname(void);

void *setmode(const char *mode);
mode_t getmode(const void *set, mode_t mode);

int uid_from_user(const char *name, uid_t *uid);
int gid_from_group(const char *name, gid_t *gid);

#endif /* ARMOS_BSDINSTALL_UTIL_H */
