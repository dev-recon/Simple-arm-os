#ifndef ARMOS_BSDMTREE_UTIL_H
#define ARMOS_BSDMTREE_UTIL_H

#include <sys/types.h>

void setprogname(const char *name);
const char *getprogname(void);

void *setmode(const char *mode);
mode_t getmode(const void *set, mode_t mode);

int uid_from_user(const char *name, uid_t *uid);
int gid_from_group(const char *name, gid_t *gid);
const char *user_from_uid(uid_t uid, int nouser);
const char *group_from_gid(gid_t gid, int nogroup);

char *flags_to_string(unsigned long flags, const char *def);
int string_to_flags(char **stringp, unsigned long *setp, unsigned long *clrp);

#endif /* ARMOS_BSDMTREE_UTIL_H */
