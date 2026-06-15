#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

static int parse_uint(const char *s, unsigned *out)
{
    unsigned value = 0;

    if (!s || !*s || !out)
        return -1;

    while (*s) {
        if (*s < '0' || *s > '9')
            return -1;
        value = value * 10u + (unsigned)(*s - '0');
        s++;
    }

    *out = value;
    return 0;
}

static int parse_owner_group(const char *spec, uid_t *owner, gid_t *group)
{
    char owner_buf[16];
    char group_buf[16];
    int owner_len = 0;
    int group_len = 0;
    int seen_colon = 0;
    unsigned value;

    if (!spec || !*spec || !owner || !group)
        return -1;

    *owner = (uid_t)-1;
    *group = (gid_t)-1;

    for (const char *p = spec; *p; p++) {
        if (*p == ':') {
            if (seen_colon)
                return -1;
            seen_colon = 1;
            continue;
        }

        if (!seen_colon) {
            if (owner_len >= (int)sizeof(owner_buf) - 1)
                return -1;
            owner_buf[owner_len++] = *p;
        } else {
            if (group_len >= (int)sizeof(group_buf) - 1)
                return -1;
            group_buf[group_len++] = *p;
        }
    }

    owner_buf[owner_len] = '\0';
    group_buf[group_len] = '\0';

    if (owner_len > 0) {
        if (parse_uint(owner_buf, &value) < 0)
            return -1;
        *owner = (uid_t)value;
    }

    if (seen_colon && group_len > 0) {
        if (parse_uint(group_buf, &value) < 0)
            return -1;
        *group = (gid_t)value;
    }

    if (*owner == (uid_t)-1 && *group == (gid_t)-1)
        return -1;

    return 0;
}

int main(int argc, char **argv)
{
    uid_t owner;
    gid_t group;
    int status = 0;

    if (argc < 3) {
        printf("Usage: chown OWNER[:GROUP] FILE...\n");
        return 1;
    }

    if (parse_owner_group(argv[1], &owner, &group) < 0) {
        printf("chown: invalid owner '%s'\n", argv[1]);
        return 1;
    }

    for (int i = 2; i < argc; i++) {
        errno = 0;
        if (chown(argv[i], owner, group) < 0) {
            printf("chown: cannot change owner of '%s' (errno=%d)\n", argv[i], errno);
            status = 1;
        }
    }

    return status;
}
