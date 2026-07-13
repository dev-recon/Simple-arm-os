/*
 * ArmOS syscall ABI constants shared by architecture entry paths.
 *
 * The number space remains Linux ARM32 compatible for the existing ArmOS
 * userland. Each architecture defines its own register calling convention.
 */

#ifndef _UAPI_ARMOS_SYSCALL_H
#define _UAPI_ARMOS_SYSCALL_H

#define ARMOS_NR_EXIT       1
#define ARMOS_NR_WRITE      4
#define ARMOS_SYSCALL_MAX 512

#endif
