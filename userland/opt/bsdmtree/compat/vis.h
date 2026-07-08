#ifndef ARMOS_BSDMTREE_VIS_H
#define ARMOS_BSDMTREE_VIS_H

#define VIS_CSTYLE 0x0001
#define VIS_OCTAL 0x0002

int strsvis(char *dst, const char *src, int flags, const char *extra);
int strunvis(char *dst, const char *src);

#endif /* ARMOS_BSDMTREE_VIS_H */
