#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef SHF_EXECINSTR
#define SHF_EXECINSTR 0x4
#endif

#ifndef SHN_UNDEF
#define SHN_UNDEF 0
#endif

#ifndef SHN_ABS
#define SHN_ABS 0xfff1
#endif

#ifndef ELF32_ST_BIND
#define ELF32_ST_BIND(i) ((i) >> 4)
#endif

#ifndef ELF32_ST_TYPE
#define ELF32_ST_TYPE(i) ((i) & 0xf)
#endif

#ifndef STB_LOCAL
#define STB_LOCAL 0
#endif

#ifndef STB_GLOBAL
#define STB_GLOBAL 1
#endif

#ifndef STB_WEAK
#define STB_WEAK 2
#endif

#ifndef STT_NOTYPE
#define STT_NOTYPE 0
#endif

#ifndef STT_OBJECT
#define STT_OBJECT 1
#endif

#ifndef STT_FUNC
#define STT_FUNC 2
#endif

#ifndef STT_SECTION
#define STT_SECTION 3
#endif

#ifndef STT_FILE
#define STT_FILE 4
#endif

#ifndef PT_LOAD
#define PT_LOAD 1
#endif

#define ARMAG "!<arch>\n"
#define SARMAG 8
#define ARFMAG "`\n"

struct ar_hdr {
    char ar_name[16];
    char ar_date[12];
    char ar_uid[6];
    char ar_gid[6];
    char ar_mode[8];
    char ar_size[10];
    char ar_fmag[2];
};

struct member {
    char *name;
    unsigned char *data;
    size_t size;
    mode_t mode;
    time_t mtime;
};

struct members {
    struct member *items;
    size_t len;
    size_t cap;
};

struct ar_symbol {
    char *name;
    size_t member_index;
};

struct ar_symbols {
    struct ar_symbol *items;
    size_t len;
    size_t cap;
    size_t names_size;
};

struct nm_symbol {
    const char *name;
    uint32_t value;
    unsigned char type;
    unsigned char bind;
    uint16_t shndx;
};

static const char *progname = "elftools";

static void
set_progname(const char *path)
{
    const char *slash = strrchr(path, '/');

    progname = slash ? slash + 1 : path;
}

static void
die(const char *msg)
{
    fprintf(stderr, "%s: %s: %s\n", progname, msg, strerror(errno));
    exit(1);
}

static void
diex(const char *msg)
{
    fprintf(stderr, "%s: %s\n", progname, msg);
    exit(1);
}

static void *
xmalloc(size_t size)
{
    void *p = malloc(size ? size : 1);

    if (p == NULL)
        die("malloc");
    return p;
}

static void *
xrealloc(void *old, size_t size)
{
    void *p = realloc(old, size ? size : 1);

    if (p == NULL)
        die("realloc");
    return p;
}

static char *
xstrdup(const char *s)
{
    char *p = strdup(s);

    if (p == NULL)
        die("strdup");
    return p;
}

static const char *
base_name(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash ? slash + 1 : path;
}

static int
read_file(const char *path, unsigned char **datap, size_t *sizep,
    struct stat *stp)
{
    FILE *fp;
    unsigned char *data;
    long len;
    struct stat st;

    fp = fopen(path, "rb");
    if (fp == NULL)
        return -1;
    if (fstat(fileno(fp), &st) != 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    len = ftell(fp);
    if (len < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    data = xmalloc((size_t)len);
    if (len != 0 && fread(data, 1, (size_t)len, fp) != (size_t)len) {
        free(data);
        fclose(fp);
        errno = EIO;
        return -1;
    }
    fclose(fp);
    *datap = data;
    *sizep = (size_t)len;
    if (stp != NULL)
        *stp = st;
    return 0;
}

static int
write_file_mode(const char *path, const unsigned char *data, size_t size,
    mode_t mode)
{
    FILE *fp = fopen(path, "wb");

    if (fp == NULL)
        return -1;
    if (size != 0 && fwrite(data, 1, size, fp) != size) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    chmod(path, mode);
    return 0;
}

static int
is_archive_data(const unsigned char *data, size_t size)
{
    return size >= SARMAG && memcmp(data, ARMAG, SARMAG) == 0;
}

static int
is_elf32le(const unsigned char *data, size_t size)
{
    const Elf32_Ehdr *eh;

    if (size < sizeof(*eh))
        return 0;
    eh = (const Elf32_Ehdr *)data;
    return eh->e_ident[EI_MAG0] == ELFMAG0 &&
        eh->e_ident[EI_MAG1] == ELFMAG1 &&
        eh->e_ident[EI_MAG2] == ELFMAG2 &&
        eh->e_ident[EI_MAG3] == ELFMAG3 &&
        eh->e_ident[EI_CLASS] == ELFCLASS32 &&
        eh->e_ident[EI_DATA] == ELFDATA2LSB;
}

static long
parse_ar_decimal(const char *field, size_t len)
{
    char buf[32];
    size_t n = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;

    memcpy(buf, field, n);
    buf[n] = '\0';
    return strtol(buf, NULL, 10);
}

static long
parse_ar_octal(const char *field, size_t len)
{
    char buf[32];
    size_t n = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;

    memcpy(buf, field, n);
    buf[n] = '\0';
    return strtol(buf, NULL, 8);
}

static void
format_field(char *dst, size_t len, long value, int base)
{
    char buf[32];
    size_t n;

    if (base == 8)
        snprintf(buf, sizeof(buf), "%lo", value);
    else
        snprintf(buf, sizeof(buf), "%ld", value);
    n = strlen(buf);
    if (n > len)
        diex("archive header field overflow");
    memset(dst, ' ', len);
    memcpy(dst, buf, n);
}

static int
replace_file(const char *tmp, const char *path)
{
    int saved_errno;

    if (rename(tmp, path) == 0)
        return 0;

    saved_errno = errno;
    if ((saved_errno == EEXIST || saved_errno == EINVAL) &&
        access(path, F_OK) == 0) {
        if (unlink(path) != 0)
            return -1;
        if (rename(tmp, path) == 0)
            return 0;
        return -1;
    }
    errno = saved_errno;
    return -1;
}

static void
members_push(struct members *members, struct member member)
{
    if (members->len == members->cap) {
        members->cap = members->cap ? members->cap * 2 : 8;
        members->items = xrealloc(members->items,
            members->cap * sizeof(members->items[0]));
    }
    members->items[members->len++] = member;
}

static void
members_free(struct members *members)
{
    size_t i;

    for (i = 0; i < members->len; i++) {
        free(members->items[i].name);
        free(members->items[i].data);
    }
    free(members->items);
    members->items = NULL;
    members->len = members->cap = 0;
}

static void
symbols_push(struct ar_symbols *symbols, const char *name, size_t member_index)
{
    if (symbols->len == symbols->cap) {
        symbols->cap = symbols->cap ? symbols->cap * 2 : 32;
        symbols->items = xrealloc(symbols->items,
            symbols->cap * sizeof(symbols->items[0]));
    }
    symbols->items[symbols->len].name = xstrdup(name);
    symbols->items[symbols->len].member_index = member_index;
    symbols->names_size += strlen(name) + 1;
    symbols->len++;
}

static void
symbols_free(struct ar_symbols *symbols)
{
    size_t i;

    for (i = 0; i < symbols->len; i++)
        free(symbols->items[i].name);
    free(symbols->items);
    memset(symbols, 0, sizeof(*symbols));
}

static uint32_t
to_be32(uint32_t value)
{
    return ((value & 0x000000ffU) << 24) |
        ((value & 0x0000ff00U) << 8) |
        ((value & 0x00ff0000U) >> 8) |
        ((value & 0xff000000U) >> 24);
}

static char *
trim_ar_name(const char *field)
{
    char tmp[17];
    size_t len = sizeof(tmp) - 1;

    memcpy(tmp, field, len);
    while (len > 0 && tmp[len - 1] == ' ')
        len--;
    tmp[len] = '\0';
    return xstrdup(tmp);
}

static char *
gnu_long_name(const char *longnames, size_t longnames_size, long offset)
{
    size_t start;
    size_t end;
    char *name;

    if (offset < 0 || (size_t)offset >= longnames_size)
        return NULL;
    start = (size_t)offset;
    end = start;
    while (end < longnames_size && longnames[end] != '\n')
        end++;
    if (end > start && longnames[end - 1] == '/')
        end--;
    name = xmalloc(end - start + 1);
    memcpy(name, longnames + start, end - start);
    name[end - start] = '\0';
    return name;
}

static int
read_archive_members(const char *path, struct members *members)
{
    unsigned char *data = NULL;
    size_t size = 0;
    size_t pos;
    char *longnames = NULL;
    size_t longnames_size = 0;
    int ret = -1;

    memset(members, 0, sizeof(*members));
    if (read_file(path, &data, &size, NULL) != 0)
        return -1;
    if (!is_archive_data(data, size)) {
        errno = EINVAL;
        goto out;
    }

    pos = SARMAG;
    while (pos + sizeof(struct ar_hdr) <= size) {
        struct ar_hdr hdr;
        char *raw;
        char *name = NULL;
        long member_size_long;
        size_t member_size;
        size_t data_pos;
        size_t data_size;

        memcpy(&hdr, data + pos, sizeof(hdr));
        if (memcmp(hdr.ar_fmag, ARFMAG, 2) != 0) {
            errno = EINVAL;
            goto out;
        }
        pos += sizeof(hdr);
        member_size_long = parse_ar_decimal(hdr.ar_size, sizeof(hdr.ar_size));
        if (member_size_long < 0 || pos + (size_t)member_size_long > size) {
            errno = EINVAL;
            goto out;
        }
        member_size = (size_t)member_size_long;
        data_pos = pos;
        data_size = member_size;
        raw = trim_ar_name(hdr.ar_name);

        if (strcmp(raw, "//") == 0) {
            free(longnames);
            longnames = xmalloc(data_size + 1);
            memcpy(longnames, data + data_pos, data_size);
            longnames[data_size] = '\0';
            longnames_size = data_size;
            free(raw);
            goto next;
        }
        if (strcmp(raw, "/") == 0 || strcmp(raw, "/SYM64/") == 0 ||
            strcmp(raw, "__.SYMDEF") == 0) {
            free(raw);
            goto next;
        }
        if (strncmp(raw, "#1/", 3) == 0) {
            long name_len = strtol(raw + 3, NULL, 10);

            if (name_len < 0 || (size_t)name_len > data_size) {
                free(raw);
                errno = EINVAL;
                goto out;
            }
            name = xmalloc((size_t)name_len + 1);
            memcpy(name, data + data_pos, (size_t)name_len);
            name[name_len] = '\0';
            data_pos += (size_t)name_len;
            data_size -= (size_t)name_len;
            free(raw);
        } else if (raw[0] == '/' && isdigit((unsigned char)raw[1])) {
            name = gnu_long_name(longnames, longnames_size, strtol(raw + 1, NULL, 10));
            free(raw);
            if (name == NULL) {
                errno = EINVAL;
                goto out;
            }
        } else {
            size_t raw_len = strlen(raw);

            if (raw_len > 0 && raw[raw_len - 1] == '/')
                raw[raw_len - 1] = '\0';
            name = raw;
        }

        if (name != NULL) {
            struct member member;

            member.name = name;
            member.data = xmalloc(data_size);
            memcpy(member.data, data + data_pos, data_size);
            member.size = data_size;
            member.mode = (mode_t)parse_ar_octal(hdr.ar_mode, sizeof(hdr.ar_mode));
            member.mtime = (time_t)parse_ar_decimal(hdr.ar_date, sizeof(hdr.ar_date));
            members_push(members, member);
        }

next:
        pos += member_size;
        if (pos & 1)
            pos++;
    }
    ret = 0;

out:
    free(longnames);
    free(data);
    if (ret != 0)
        members_free(members);
    return ret;
}

static int
member_name_matches(const char *member_name, const char *arg)
{
    return strcmp(member_name, arg) == 0 ||
        strcmp(member_name, base_name(arg)) == 0;
}

static int
member_selected(const struct member *member, int argc, char **argv)
{
    int i;

    if (argc == 0)
        return 1;
    for (i = 0; i < argc; i++) {
        if (member_name_matches(member->name, argv[i]))
            return 1;
    }
    return 0;
}

static struct member
member_from_file(const char *path)
{
    struct member member;
    struct stat st;

    memset(&member, 0, sizeof(member));
    if (read_file(path, &member.data, &member.size, &st) != 0) {
        fprintf(stderr, "%s: %s: %s\n", progname, path, strerror(errno));
        exit(1);
    }
    member.name = xstrdup(base_name(path));
    member.mode = st.st_mode & 0777;
    member.mtime = st.st_mtime;
    return member;
}

static int
valid_shdr_table(const unsigned char *data, size_t size, const Elf32_Ehdr *eh)
{
    size_t table_size;

    if (eh->e_shoff == 0 || eh->e_shnum == 0)
        return 0;
    if (eh->e_shentsize != sizeof(Elf32_Shdr))
        return 0;
    table_size = (size_t)eh->e_shnum * sizeof(Elf32_Shdr);
    return eh->e_shoff <= size && table_size <= size - eh->e_shoff;
}

static const char *
section_name(const unsigned char *data, size_t size, const Elf32_Ehdr *eh,
    const Elf32_Shdr *shdrs, size_t index)
{
    const Elf32_Shdr *shstr;

    if (eh->e_shstrndx == SHN_UNDEF || eh->e_shstrndx >= eh->e_shnum)
        return "";
    shstr = &shdrs[eh->e_shstrndx];
    if (shstr->sh_offset >= size || shstr->sh_name >= shstr->sh_size)
        return "";
    if (index >= eh->e_shnum)
        return "";
    if (shdrs[index].sh_name >= shstr->sh_size)
        return "";
    return (const char *)data + shstr->sh_offset + shdrs[index].sh_name;
}

static void
collect_member_symbols(const struct member *member, size_t member_index,
    struct ar_symbols *symbols)
{
    const Elf32_Ehdr *eh;
    const Elf32_Shdr *shdrs;
    size_t i;

    if (!is_elf32le(member->data, member->size))
        return;
    eh = (const Elf32_Ehdr *)member->data;
    if (!valid_shdr_table(member->data, member->size, eh))
        return;
    shdrs = (const Elf32_Shdr *)(member->data + eh->e_shoff);

    for (i = 0; i < eh->e_shnum; i++) {
        const Elf32_Shdr *symsec = &shdrs[i];
        const Elf32_Shdr *strsec;
        const Elf32_Sym *syms;
        const char *strtab;
        size_t nsym;
        size_t j;

        if (symsec->sh_type != SHT_SYMTAB || symsec->sh_entsize != sizeof(Elf32_Sym))
            continue;
        if (symsec->sh_link >= eh->e_shnum)
            continue;
        strsec = &shdrs[symsec->sh_link];
        if (symsec->sh_offset > member->size || symsec->sh_size > member->size - symsec->sh_offset)
            continue;
        if (strsec->sh_offset > member->size || strsec->sh_size > member->size - strsec->sh_offset)
            continue;
        syms = (const Elf32_Sym *)(member->data + symsec->sh_offset);
        strtab = (const char *)member->data + strsec->sh_offset;
        nsym = symsec->sh_size / sizeof(Elf32_Sym);
        for (j = 1; j < nsym; j++) {
            unsigned bind = ELF32_ST_BIND(syms[j].st_info);
            unsigned type = ELF32_ST_TYPE(syms[j].st_info);
            const char *name;

            if (syms[j].st_name >= strsec->sh_size)
                continue;
            name = strtab + syms[j].st_name;
            if (*name == '\0')
                continue;
            if (syms[j].st_shndx == SHN_UNDEF)
                continue;
            if (bind != STB_GLOBAL && bind != STB_WEAK)
                continue;
            if (type != STT_NOTYPE && type != STT_OBJECT && type != STT_FUNC)
                continue;
            symbols_push(symbols, name, member_index);
        }
    }
}

static void
write_ar_header(FILE *fp, const char *name, size_t size, mode_t mode, time_t mtime)
{
    struct ar_hdr hdr;
    size_t name_len = strlen(name);

    if (name_len > 15)
        diex("archive member name too long for current ArmOS ar");
    memset(&hdr, ' ', sizeof(hdr));
    memcpy(hdr.ar_name, name, name_len);
    hdr.ar_name[name_len] = '/';
    format_field(hdr.ar_date, sizeof(hdr.ar_date), (long)mtime, 10);
    format_field(hdr.ar_uid, sizeof(hdr.ar_uid), 0, 10);
    format_field(hdr.ar_gid, sizeof(hdr.ar_gid), 0, 10);
    format_field(hdr.ar_mode, sizeof(hdr.ar_mode), mode ? (long)(mode & 0777) : 0644, 8);
    format_field(hdr.ar_size, sizeof(hdr.ar_size), (long)size, 10);
    memcpy(hdr.ar_fmag, ARFMAG, 2);
    if (fwrite(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr))
        die("archive write");
}

static void
write_symbol_header(FILE *fp, size_t size)
{
    struct ar_hdr hdr;

    memset(&hdr, ' ', sizeof(hdr));
    hdr.ar_name[0] = '/';
    format_field(hdr.ar_date, sizeof(hdr.ar_date), 0, 10);
    format_field(hdr.ar_uid, sizeof(hdr.ar_uid), 0, 10);
    format_field(hdr.ar_gid, sizeof(hdr.ar_gid), 0, 10);
    format_field(hdr.ar_mode, sizeof(hdr.ar_mode), 0644, 8);
    format_field(hdr.ar_size, sizeof(hdr.ar_size), (long)size, 10);
    memcpy(hdr.ar_fmag, ARFMAG, 2);
    if (fwrite(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr))
        die("archive symbol header write");
}

static void
write_archive(const char *path, const struct members *members, int with_index)
{
    char tmp[PATH_MAX];
    FILE *fp;
    struct ar_symbols symbols;
    uint32_t *member_offsets = NULL;
    size_t symtab_size = 0;
    size_t first_member_offset;
    size_t off;
    size_t i;

    memset(&symbols, 0, sizeof(symbols));
    if (with_index) {
        for (i = 0; i < members->len; i++)
            collect_member_symbols(&members->items[i], i, &symbols);
    }
    if (symbols.len != 0)
        symtab_size = sizeof(uint32_t) + symbols.len * sizeof(uint32_t) +
            symbols.names_size;

    first_member_offset = SARMAG;
    if (symtab_size != 0)
        first_member_offset += sizeof(struct ar_hdr) + symtab_size + (symtab_size & 1);
    member_offsets = xmalloc(sizeof(uint32_t) * (members->len ? members->len : 1));
    off = first_member_offset;
    for (i = 0; i < members->len; i++) {
        member_offsets[i] = (uint32_t)off;
        off += sizeof(struct ar_hdr) + members->items[i].size +
            (members->items[i].size & 1);
    }

    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    fp = fopen(tmp, "wb");
    if (fp == NULL)
        die(tmp);
    if (fwrite(ARMAG, 1, SARMAG, fp) != SARMAG)
        die("archive magic write");

    if (symtab_size != 0) {
        uint32_t be_count = to_be32((uint32_t)symbols.len);

        write_symbol_header(fp, symtab_size);
        if (fwrite(&be_count, 1, sizeof(be_count), fp) != sizeof(be_count))
            die("archive symbol count write");
        for (i = 0; i < symbols.len; i++) {
            uint32_t be_off = to_be32(member_offsets[symbols.items[i].member_index]);

            if (fwrite(&be_off, 1, sizeof(be_off), fp) != sizeof(be_off))
                die("archive symbol offset write");
        }
        for (i = 0; i < symbols.len; i++) {
            size_t len = strlen(symbols.items[i].name) + 1;

            if (fwrite(symbols.items[i].name, 1, len, fp) != len)
                die("archive symbol name write");
        }
        if (symtab_size & 1)
            fputc('\n', fp);
    }

    for (i = 0; i < members->len; i++) {
        const struct member *member = &members->items[i];

        write_ar_header(fp, member->name, member->size, member->mode, member->mtime);
        if (member->size != 0 &&
            fwrite(member->data, 1, member->size, fp) != member->size)
            die("archive member write");
        if (member->size & 1)
            fputc('\n', fp);
    }
    if (fclose(fp) != 0)
        die(tmp);
    if (replace_file(tmp, path) != 0)
        die(path);
    free(member_offsets);
    symbols_free(&symbols);
}

static void
ar_usage(void)
{
    fprintf(stderr, "usage: ar [-]d|p|q|r|s|t|x[csv] archive [file ...]\n");
    exit(1);
}

static int
run_ar(int argc, char **argv)
{
    const char *opts;
    const char *archive;
    struct members members;
    int opt_index = 1;
    int arg_index;
    int verbose = 0;
    int with_index = 0;
    char op = '\0';
    size_t i;

    if (argc < 3)
        ar_usage();
    opts = argv[opt_index];
    if (opts[0] == '-')
        opts++;
    for (i = 0; opts[i] != '\0'; i++) {
        switch (opts[i]) {
        case 'd':
        case 'p':
        case 'q':
        case 'r':
        case 's':
        case 't':
        case 'x':
            if (op == '\0')
                op = opts[i];
            else if (opts[i] != 's')
                ar_usage();
            if (opts[i] == 's')
                with_index = 1;
            break;
        case 'c':
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            ar_usage();
        }
    }
    if (op == '\0')
        ar_usage();
    archive = argv[++opt_index];
    arg_index = opt_index + 1;

    memset(&members, 0, sizeof(members));
    if (op == 'r' || op == 'q' || op == 'd' || op == 's') {
        if (access(archive, F_OK) == 0) {
            if (read_archive_members(archive, &members) != 0)
                die(archive);
        }
    } else {
        if (read_archive_members(archive, &members) != 0)
            die(archive);
    }

    if (op == 't') {
        for (i = 0; i < members.len; i++) {
            if (member_selected(&members.items[i], argc - arg_index, argv + arg_index))
                printf("%s\n", members.items[i].name);
        }
    } else if (op == 'p') {
        for (i = 0; i < members.len; i++) {
            if (member_selected(&members.items[i], argc - arg_index, argv + arg_index))
                fwrite(members.items[i].data, 1, members.items[i].size, stdout);
        }
    } else if (op == 'x') {
        for (i = 0; i < members.len; i++) {
            if (!member_selected(&members.items[i], argc - arg_index, argv + arg_index))
                continue;
            if (verbose)
                printf("x - %s\n", members.items[i].name);
            if (write_file_mode(members.items[i].name, members.items[i].data,
                members.items[i].size, members.items[i].mode) != 0)
                die(members.items[i].name);
        }
    } else if (op == 'd') {
        struct members kept;

        memset(&kept, 0, sizeof(kept));
        for (i = 0; i < members.len; i++) {
            if (member_selected(&members.items[i], argc - arg_index, argv + arg_index)) {
                if (verbose)
                    printf("d - %s\n", members.items[i].name);
                free(members.items[i].name);
                free(members.items[i].data);
            } else {
                members_push(&kept, members.items[i]);
            }
        }
        free(members.items);
        members = kept;
        write_archive(archive, &members, with_index);
    } else if (op == 'r' || op == 'q') {
        int a;

        for (a = arg_index; a < argc; a++) {
            struct member new_member = member_from_file(argv[a]);
            int replaced = 0;

            if (op == 'r') {
                for (i = 0; i < members.len; i++) {
                    if (strcmp(members.items[i].name, new_member.name) == 0) {
                        if (verbose)
                            printf("r - %s\n", new_member.name);
                        free(members.items[i].name);
                        free(members.items[i].data);
                        members.items[i] = new_member;
                        replaced = 1;
                        break;
                    }
                }
            }
            if (!replaced) {
                if (verbose)
                    printf("a - %s\n", new_member.name);
                members_push(&members, new_member);
            }
        }
        write_archive(archive, &members, with_index || strchr(opts, 's') != NULL);
    } else if (op == 's') {
        write_archive(archive, &members, 1);
    }

    members_free(&members);
    return 0;
}

static int
run_ranlib(int argc, char **argv)
{
    int i;

    if (argc < 2) {
        fprintf(stderr, "usage: ranlib archive ...\n");
        return 1;
    }
    for (i = 1; i < argc; i++) {
        struct members members;

        if (read_archive_members(argv[i], &members) != 0)
            die(argv[i]);
        write_archive(argv[i], &members, 1);
        members_free(&members);
    }
    return 0;
}

static char
nm_type_for_symbol(const unsigned char *data, size_t size, const Elf32_Ehdr *eh,
    const Elf32_Shdr *shdrs, const Elf32_Sym *sym)
{
    char c = '?';
    unsigned bind = ELF32_ST_BIND(sym->st_info);

    if (sym->st_shndx == SHN_UNDEF)
        c = 'U';
    else if (sym->st_shndx == SHN_ABS)
        c = 'A';
    else if (bind == STB_WEAK)
        c = 'W';
    else if (sym->st_shndx < eh->e_shnum) {
        const Elf32_Shdr *sec = &shdrs[sym->st_shndx];
        const char *name = section_name(data, size, eh, shdrs, sym->st_shndx);

        if (sec->sh_type == SHT_NOBITS)
            c = 'B';
        else if (sec->sh_flags & SHF_EXECINSTR)
            c = 'T';
        else if (sec->sh_flags & SHF_WRITE)
            c = 'D';
        else if (sec->sh_flags & SHF_ALLOC)
            c = 'R';
        else if (strcmp(name, ".debug") == 0 || strncmp(name, ".debug_", 7) == 0)
            c = 'N';
    }
    if (bind == STB_LOCAL && c != '?' && c != 'U')
        c = (char)tolower((unsigned char)c);
    return c;
}

static int
print_nm_elf(const unsigned char *data, size_t size, const char *label,
    int prefix, int global_only, int undefined_only)
{
    const Elf32_Ehdr *eh;
    const Elf32_Shdr *shdrs;
    int printed = 0;
    size_t i;

    if (!is_elf32le(data, size))
        return -1;
    eh = (const Elf32_Ehdr *)data;
    if (!valid_shdr_table(data, size, eh))
        return -1;
    shdrs = (const Elf32_Shdr *)(data + eh->e_shoff);

    for (i = 0; i < eh->e_shnum; i++) {
        const Elf32_Shdr *symsec = &shdrs[i];
        const Elf32_Shdr *strsec;
        const Elf32_Sym *syms;
        const char *strtab;
        size_t nsym;
        size_t j;

        if (symsec->sh_type != SHT_SYMTAB || symsec->sh_entsize != sizeof(Elf32_Sym))
            continue;
        if (symsec->sh_link >= eh->e_shnum)
            continue;
        strsec = &shdrs[symsec->sh_link];
        if (symsec->sh_offset > size || symsec->sh_size > size - symsec->sh_offset)
            continue;
        if (strsec->sh_offset > size || strsec->sh_size > size - strsec->sh_offset)
            continue;
        syms = (const Elf32_Sym *)(data + symsec->sh_offset);
        strtab = (const char *)data + strsec->sh_offset;
        nsym = symsec->sh_size / sizeof(Elf32_Sym);
        for (j = 1; j < nsym; j++) {
            const Elf32_Sym *sym = &syms[j];
            const char *name;
            unsigned bind = ELF32_ST_BIND(sym->st_info);
            unsigned type = ELF32_ST_TYPE(sym->st_info);
            char c;

            if (sym->st_name >= strsec->sh_size)
                continue;
            name = strtab + sym->st_name;
            if (*name == '\0')
                continue;
            if (type == STT_SECTION || type == STT_FILE)
                continue;
            if (global_only && bind == STB_LOCAL)
                continue;
            if (undefined_only && sym->st_shndx != SHN_UNDEF)
                continue;
            c = nm_type_for_symbol(data, size, eh, shdrs, sym);
            if (prefix)
                printf("%s: ", label);
            if (sym->st_shndx == SHN_UNDEF)
                printf("         %c %s\n", c, name);
            else
                printf("%08lx %c %s\n", (unsigned long)sym->st_value, c, name);
            printed = 1;
        }
    }
    return printed ? 0 : -1;
}

static int
run_nm(int argc, char **argv)
{
    int global_only = 0;
    int undefined_only = 0;
    int argi = 1;
    int file_count;
    int i;

    while (argi < argc && argv[argi][0] == '-') {
        const char *opt = argv[argi++] + 1;

        while (*opt) {
            if (*opt == 'g')
                global_only = 1;
            else if (*opt == 'u')
                undefined_only = 1;
            else if (*opt != 'A' && *opt != 'a' && *opt != 'n')
                fprintf(stderr, "%s: warning: option -%c ignored\n", progname, *opt);
            opt++;
        }
    }
    file_count = argc - argi;
    if (file_count == 0) {
        argv[argc++] = "a.out";
        file_count = 1;
    }
    for (i = argi; i < argc; i++) {
        unsigned char *data;
        size_t size;

        if (read_file(argv[i], &data, &size, NULL) != 0)
            die(argv[i]);
        if (is_archive_data(data, size)) {
            struct members members;
            size_t m;

            free(data);
            if (read_archive_members(argv[i], &members) != 0)
                die(argv[i]);
            for (m = 0; m < members.len; m++) {
                char label[PATH_MAX];

                snprintf(label, sizeof(label), "%s(%s)", argv[i], members.items[m].name);
                print_nm_elf(members.items[m].data, members.items[m].size, label,
                    1, global_only, undefined_only);
            }
            members_free(&members);
        } else {
            if (print_nm_elf(data, size, argv[i], file_count > 1,
                global_only, undefined_only) != 0)
                fprintf(stderr, "%s: %s: no symbols\n", progname, argv[i]);
            free(data);
        }
    }
    return 0;
}

static int
print_size_elf(const unsigned char *data, size_t size, const char *label)
{
    const Elf32_Ehdr *eh;
    const Elf32_Shdr *shdrs;
    unsigned long text = 0;
    unsigned long data_size = 0;
    unsigned long bss = 0;
    size_t i;

    if (!is_elf32le(data, size))
        return -1;
    eh = (const Elf32_Ehdr *)data;
    if (!valid_shdr_table(data, size, eh))
        return -1;
    shdrs = (const Elf32_Shdr *)(data + eh->e_shoff);
    for (i = 0; i < eh->e_shnum; i++) {
        const Elf32_Shdr *sec = &shdrs[i];

        if ((sec->sh_flags & SHF_ALLOC) == 0)
            continue;
        if (sec->sh_type == SHT_NOBITS)
            bss += sec->sh_size;
        else if (sec->sh_flags & SHF_WRITE)
            data_size += sec->sh_size;
        else
            text += sec->sh_size;
    }
    printf("%lu\t%lu\t%lu\t%lu\t%lx\t%s\n", text, data_size, bss,
        text + data_size + bss, text + data_size + bss, label);
    return 0;
}

static int
run_size(int argc, char **argv)
{
    int argi = 1;
    int i;

    while (argi < argc && argv[argi][0] == '-')
        argi++;
    if (argi == argc)
        argv[argc++] = "a.out";
    printf("text\tdata\tbss\tdec\thex\tfilename\n");
    for (i = argi; i < argc; i++) {
        unsigned char *data;
        size_t size;

        if (read_file(argv[i], &data, &size, NULL) != 0)
            die(argv[i]);
        if (is_archive_data(data, size)) {
            struct members members;
            size_t m;

            free(data);
            if (read_archive_members(argv[i], &members) != 0)
                die(argv[i]);
            for (m = 0; m < members.len; m++) {
                char label[PATH_MAX];

                snprintf(label, sizeof(label), "%s(%s)", argv[i], members.items[m].name);
                print_size_elf(members.items[m].data, members.items[m].size, label);
            }
            members_free(&members);
        } else {
            if (print_size_elf(data, size, argv[i]) != 0)
                fprintf(stderr, "%s: %s: not an ELF file\n", progname, argv[i]);
            free(data);
        }
    }
    return 0;
}

static int
strip_one(const char *input, const char *output)
{
    unsigned char *data;
    size_t size;
    struct stat st;
    Elf32_Ehdr *eh;
    const Elf32_Phdr *phdrs;
    size_t keep;
    size_t ph_end;
    size_t i;
    unsigned char *out;
    char tmp[PATH_MAX];

    if (read_file(input, &data, &size, &st) != 0)
        die(input);
    if (!is_elf32le(data, size)) {
        free(data);
        fprintf(stderr, "%s: %s: not an ELF32 little-endian file\n", progname, input);
        return 1;
    }
    eh = (Elf32_Ehdr *)data;
    if (eh->e_type == ET_REL) {
        free(data);
        fprintf(stderr, "%s: %s: refusing to strip relocatable object\n", progname, input);
        return 1;
    }
    keep = eh->e_ehsize;
    if (eh->e_phoff != 0 && eh->e_phentsize == sizeof(Elf32_Phdr)) {
        ph_end = eh->e_phoff + (size_t)eh->e_phnum * sizeof(Elf32_Phdr);
        if (ph_end > size) {
            free(data);
            fprintf(stderr, "%s: %s: invalid program header table\n", progname, input);
            return 1;
        }
        if (ph_end > keep)
            keep = ph_end;
        phdrs = (const Elf32_Phdr *)(data + eh->e_phoff);
        for (i = 0; i < eh->e_phnum; i++) {
            size_t end;

            if (phdrs[i].p_type != PT_LOAD)
                continue;
            end = phdrs[i].p_offset + phdrs[i].p_filesz;
            if (end > keep)
                keep = end;
        }
    }
    if (keep > size)
        keep = size;
    out = xmalloc(keep);
    memcpy(out, data, keep);
    eh = (Elf32_Ehdr *)out;
    eh->e_shoff = 0;
    eh->e_shentsize = 0;
    eh->e_shnum = 0;
    eh->e_shstrndx = SHN_UNDEF;

    if (strcmp(input, output) == 0) {
        snprintf(tmp, sizeof(tmp), "%s.striptmp", input);
        if (write_file_mode(tmp, out, keep, st.st_mode & 0777) != 0)
            die(tmp);
        if (replace_file(tmp, input) != 0)
            die(input);
    } else if (write_file_mode(output, out, keep, st.st_mode & 0777) != 0) {
        die(output);
    }
    free(out);
    free(data);
    return 0;
}

static int
run_strip(int argc, char **argv)
{
    const char *output = NULL;
    int argi = 1;
    int status = 0;

    while (argi < argc && argv[argi][0] == '-') {
        if (strcmp(argv[argi], "-o") == 0) {
            if (++argi >= argc)
                diex("strip -o requires an output path");
            output = argv[argi++];
        } else {
            argi++;
        }
    }
    if (argi >= argc) {
        fprintf(stderr, "usage: strip [-o output] file ...\n");
        return 1;
    }
    if (output != NULL && argc - argi != 1)
        diex("strip -o accepts exactly one input");
    for (; argi < argc; argi++)
        status |= strip_one(argv[argi], output ? output : argv[argi]);
    return status;
}

int
main(int argc, char **argv)
{
    set_progname(argv[0]);

    if (strcmp(progname, "ar") == 0)
        return run_ar(argc, argv);
    if (strcmp(progname, "ranlib") == 0)
        return run_ranlib(argc, argv);
    if (strcmp(progname, "nm") == 0)
        return run_nm(argc, argv);
    if (strcmp(progname, "size") == 0)
        return run_size(argc, argv);
    if (strcmp(progname, "strip") == 0)
        return run_strip(argc, argv);

    fprintf(stderr, "usage: invoke as ar, ranlib, nm, size, or strip\n");
    return 1;
}
