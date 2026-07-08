#ifndef ARMOS_BSDMTREE_FTS_H
#define ARMOS_BSDMTREE_FTS_H

#include <sys/stat.h>
#include <sys/types.h>

typedef struct _ftsent FTSENT;
typedef struct _fts FTS;

struct _ftsent {
    FTSENT *fts_cycle;
    FTSENT *fts_parent;
    FTSENT *fts_link;
    long fts_number;
    void *fts_pointer;
    char *fts_accpath;
    char *fts_path;
    char *fts_name;
    int fts_errno;
    int fts_symfd;
    unsigned short fts_pathlen;
    unsigned short fts_namelen;
    short fts_level;
    unsigned short fts_info;
    struct stat *fts_statp;

    FTSENT *fts_child;
};

struct _fts {
    FTSENT **entries;
    size_t entry_count;
    size_t entry_cap;
    size_t index;
    FTSENT *current;
    char *skip_path;
    short skip_level;
    int options;
    dev_t root_dev;
    int (*compar)(const FTSENT **, const FTSENT **);
};

#define FTS_COMFOLLOW 0x0001
#define FTS_LOGICAL 0x0002
#define FTS_NOCHDIR 0x0004
#define FTS_NOSTAT 0x0008
#define FTS_PHYSICAL 0x0010
#define FTS_SEEDOT 0x0020
#define FTS_XDEV 0x0040

#define FTS_D 1
#define FTS_DC 2
#define FTS_DEFAULT 3
#define FTS_DNR 4
#define FTS_DOT 5
#define FTS_DP 6
#define FTS_ERR 7
#define FTS_F 8
#define FTS_INIT 9
#define FTS_NS 10
#define FTS_NSOK 11
#define FTS_SL 12
#define FTS_SLNONE 13

#define FTS_AGAIN 1
#define FTS_FOLLOW 2
#define FTS_NOINSTR 3
#define FTS_SKIP 4

FTS *fts_open(char * const *argv, int options, int (*compar)(const FTSENT **, const FTSENT **));
FTSENT *fts_read(FTS *ftsp);
FTSENT *fts_children(FTS *ftsp, int instr);
int fts_set(FTS *ftsp, FTSENT *f, int instr);
int fts_close(FTS *ftsp);

#endif /* ARMOS_BSDMTREE_FTS_H */
