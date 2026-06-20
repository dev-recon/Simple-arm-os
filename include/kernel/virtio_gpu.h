#ifndef _KERNEL_VIRTIO_GPU_H
#define _KERNEL_VIRTIO_GPU_H

#include <kernel/types.h>

bool virtio_gpu_init(void);
bool virtio_gpu_is_initialized(void);
int virtio_gpu_flush(void);
void virtio_gpu_draw_test_pattern(void);

#endif
