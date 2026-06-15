#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

int data_abort_handler(uint32_t spsr_abt, uint32_t dfar, uint32_t dfsr, uint32_t *saved);

#endif
