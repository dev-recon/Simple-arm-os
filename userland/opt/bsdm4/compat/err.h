#ifndef ARMOS_BSDM4_ERR_H
#define ARMOS_BSDM4_ERR_H

#include <stdarg.h>

void warn(const char *fmt, ...);
void warnx(const char *fmt, ...);
void warnc(int code, const char *fmt, ...);
void vwarn(const char *fmt, va_list ap);
void vwarnx(const char *fmt, va_list ap);
void err(int eval, const char *fmt, ...) __attribute__((__noreturn__));
void errx(int eval, const char *fmt, ...) __attribute__((__noreturn__));
void errc(int eval, int code, const char *fmt, ...) __attribute__((__noreturn__));
void verr(int eval, const char *fmt, va_list ap) __attribute__((__noreturn__));
void verrx(int eval, const char *fmt, va_list ap) __attribute__((__noreturn__));

#endif /* ARMOS_BSDM4_ERR_H */
