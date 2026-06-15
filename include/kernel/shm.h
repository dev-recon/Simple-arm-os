#ifndef _KERNEL_SHM_H
#define _KERNEL_SHM_H

#include <kernel/types.h>

#define SHM_NAME_MAX        32
#define SHM_MAX_OBJECTS     32
#define SHM_MAX_PAGES       64

#define SHM_O_CREAT         0x01
#define SHM_O_EXCL          0x02
#define SHM_RDONLY          0x01
#define SHM_RDWR            0x02

int sys_shm_open(const char *name, size_t size, int flags);
int sys_shm_unlink(const char *name);
void *sys_shm_map(int id, void *addr, int flags);
int sys_shm_unmap(void *addr, size_t size);

void shm_retain_mapping(uint32_t shm_id);
void shm_release_mapping(uint32_t shm_id);

#endif
