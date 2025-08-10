#ifndef _KERNEL_MATH_H_
#define _KERNEL_MATH_H_

#include <kernel/types.h>

#define MOD(a, b) fast_modulo_power_of_2((a), (b))

uint16_t fast_modulo_power_of_2(uint16_t dividend, uint16_t divisor);

#endif