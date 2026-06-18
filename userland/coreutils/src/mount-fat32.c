#include <errno.h>
#include <stdio.h>

int main(void)
{
    if (mount("/dev/virtio0p2", "/mnt", "fat32", 0, NULL) < 0) {
        printf("mount-fat32: cannot mount /dev/virtio0p2 on /mnt\n");
        return errno ? errno : 1;
    }

    return 0;
}
