
#ifndef STDARG_H
#define STDARG_H


// Definitions pour remplacer stdarg.h - Compatible ARM Cortex-A9
#ifdef __GNUC__
    // GCC/Clang avec support des builtins
    typedef __builtin_va_list va_list;
    #define va_start(ap, last) __builtin_va_start(ap, last)
    #define va_arg(ap, type) __builtin_va_arg(ap, type)
    #define va_end(ap) __builtin_va_end(ap)
#else
    // Implementation manuelle pour ARM AAPCS
    typedef char* va_list;
    #define _VA_ALIGN(type) ((sizeof(type) + 3) & ~3)
    #define va_start(ap, last) ((ap) = (char*)&(last) + _VA_ALIGN(last))
    #define va_arg(ap, type) (*(type*)((ap) += _VA_ALIGN(type), (ap) - _VA_ALIGN(type)))
    #define va_end(ap) ((ap) = NULL)
#endif

#endif // STDARG_H
