/*
 * Minimal TinyCC linker probe for ArmOS.
 *
 * This does not use newlib. It only verifies whether TCC can link an ArmOS
 * executable from TCC-generated code plus syscall_raw.o.
 */

extern void sys_exit(int status);

void _start(void)
{
    sys_exit(42);
    for (;;)
        ;
}
