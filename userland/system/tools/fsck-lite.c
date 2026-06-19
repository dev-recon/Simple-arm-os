#include <stdio.h>
#include <string.h>
#include "arm_os_abi.h"

static int check_path(const char* path)
{
    struct statfs st;

    if (statfs(path, &st) < 0) {
        printf("%s: statfs failed\n", path);
        return 1;
    }

    printf("%s: block=%u blocks=%u free=%u avail=%u files=%u ffree=%u namelen=%u\n",
           path, st.f_bsize, st.f_blocks, st.f_bfree, st.f_bavail,
           st.f_files, st.f_ffree, st.f_namelen);

    if (st.f_bsize == 0 || st.f_blocks == 0) {
        printf("%s: invalid block geometry\n", path);
        return 1;
    }
    if (st.f_bfree > st.f_blocks || st.f_bavail > st.f_blocks) {
        printf("%s: inconsistent free block counters\n", path);
        return 1;
    }

    printf("%s: looks plausible\n", path);
    return 0;
}

int main(int argc, char** argv)
{
    int status = 0;

    if (argc == 1)
        return check_path("/");

    for (int i = 1; i < argc; i++) {
        if (check_path(argv[i]) != 0)
            status = 1;
    }

    return status;
}
