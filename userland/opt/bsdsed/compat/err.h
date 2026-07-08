#ifndef ARMOS_BSDSED_ERR_H
#define ARMOS_BSDSED_ERR_H

#include <stdarg.h>
#include <sys/cdefs.h>

void warn(const char *fmt, ...) __printflike(1, 2);
void warnx(const char *fmt, ...) __printflike(1, 2);
void warnc(int code, const char *fmt, ...) __printflike(2, 3);
__dead void err(int eval, const char *fmt, ...) __printflike(2, 3);
__dead void errx(int eval, const char *fmt, ...) __printflike(2, 3);
__dead void errc(int eval, int code, const char *fmt, ...) __printflike(3, 4);

#endif /* ARMOS_BSDSED_ERR_H */

