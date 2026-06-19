#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define STAT_BUF_SIZE 4096

typedef struct tty_info {
    unsigned tx_enqueued;
    unsigned tx_drained;
    unsigned tx_full_waits;
    unsigned tx_drain_calls;
    unsigned input_depth;
    unsigned input_capacity;
    unsigned eof_pending;
    unsigned iflag;
    unsigned oflag;
    unsigned lflag;
    unsigned vmin;
    unsigned vtime;
    unsigned char_wakeups;
    unsigned line_wakeups;
    unsigned eof_wakeups;
    int fg_pgid;
    int read_wait_pid;
    int read_wait_state;
    unsigned input_chars;
    unsigned ctrl_c_seen;
    unsigned sigint_delivered;
    unsigned sigint_missed;
    unsigned ctrl_z_seen;
    unsigned sigtstp_delivered;
    unsigned sigtstp_missed;
    int last_signal;
    int last_pgid;
    int last_delivered;
} tty_info_t;

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

static const char *parse_uint(const char *p, unsigned *out)
{
    unsigned value = 0;

    p = skip_ws(p);
    if (!is_digit(*p))
        return NULL;

    while (is_digit(*p)) {
        value = value * 10u + (unsigned)(*p - '0');
        p++;
    }

    *out = value;
    return p;
}

static const char *parse_int(const char *p, int *out)
{
    int sign = 1;
    unsigned value = 0;

    p = skip_ws(p);
    if (*p == '-') {
        sign = -1;
        p++;
    }
    if (!is_digit(*p))
        return NULL;

    while (is_digit(*p)) {
        value = value * 10u + (unsigned)(*p - '0');
        p++;
    }

    *out = sign * (int)value;
    return p;
}

static const char *line_after_key(const char *buf, const char *key)
{
    size_t key_len = strlen(key);
    const char *p = buf;

    while (*p) {
        const char *line = p;
        while (*p && *p != '\n')
            p++;

        if ((size_t)(p - line) >= key_len && strncmp(line, key, key_len) == 0)
            return line + key_len;

        if (*p == '\n')
            p++;
    }

    return NULL;
}

static int read_proc_stat(char *buf, int size)
{
    int fd;
    int n;

    fd = open("/proc/stat", O_RDONLY, 0);
    if (fd < 0)
        return -1;

    n = read(fd, buf, size - 1);
    close(fd);
    if (n < 0)
        return -1;

    buf[n] = '\0';
    return n;
}

static void parse_tty_info(const char *buf, tty_info_t *info)
{
    const char *p;

    memset(info, 0, sizeof(*info));

    p = line_after_key(buf, "tty_tx ");
    if (p) {
        p = parse_uint(p, &info->tx_enqueued);
        if (p) p = parse_uint(p, &info->tx_drained);
        if (p) p = parse_uint(p, &info->tx_full_waits);
        if (p) parse_uint(p, &info->tx_drain_calls);
    }

    p = line_after_key(buf, "tty_in ");
    if (p) {
        p = parse_uint(p, &info->input_depth);
        if (p) p = parse_uint(p, &info->input_capacity);
        if (p) p = parse_uint(p, &info->eof_pending);
        if (p) p = parse_uint(p, &info->iflag);
        if (p) p = parse_uint(p, &info->oflag);
        if (p) p = parse_uint(p, &info->lflag);
        if (p) p = parse_uint(p, &info->vmin);
        if (p) parse_uint(p, &info->vtime);
    }

    p = line_after_key(buf, "tty_wake ");
    if (p) {
        p = parse_uint(p, &info->char_wakeups);
        if (p) p = parse_uint(p, &info->line_wakeups);
        if (p) parse_uint(p, &info->eof_wakeups);
    }

    p = line_after_key(buf, "tty_diag ");
    while (p && *p) {
        if (strncmp(p, "fg_pgid ", 8) == 0)
            p = parse_int(p + 8, &info->fg_pgid);
        else if (strncmp(p, "read_wait_pid ", 14) == 0)
            p = parse_int(p + 14, &info->read_wait_pid);
        else if (strncmp(p, "read_wait_state ", 16) == 0)
            p = parse_int(p + 16, &info->read_wait_state);
        else if (strncmp(p, "input ", 6) == 0)
            p = parse_uint(p + 6, &info->input_chars);
        else if (strncmp(p, "ctrl_c ", 7) == 0)
            p = parse_uint(p + 7, &info->ctrl_c_seen);
        else if (strncmp(p, "sigint_delivered ", 17) == 0)
            p = parse_uint(p + 17, &info->sigint_delivered);
        else if (strncmp(p, "sigint_missed ", 14) == 0)
            p = parse_uint(p + 14, &info->sigint_missed);
        else if (strncmp(p, "ctrl_z ", 7) == 0)
            p = parse_uint(p + 7, &info->ctrl_z_seen);
        else if (strncmp(p, "sigtstp_delivered ", 18) == 0)
            p = parse_uint(p + 18, &info->sigtstp_delivered);
        else if (strncmp(p, "sigtstp_missed ", 15) == 0)
            p = parse_uint(p + 15, &info->sigtstp_missed);
        else if (strncmp(p, "last_signal ", 12) == 0)
            p = parse_int(p + 12, &info->last_signal);
        else if (strncmp(p, "last_pgid ", 10) == 0)
            p = parse_int(p + 10, &info->last_pgid);
        else if (strncmp(p, "last_delivered ", 15) == 0)
            p = parse_int(p + 15, &info->last_delivered);
        else
            break;

        if (!p)
            break;
        p = skip_ws(p);
        if (*p == '\n')
            break;
    }
}

static void print_flags(const tty_info_t *info)
{
    printf("flags: iflag=%u oflag=%u lflag=%u\n",
           info->iflag, info->oflag, info->lflag);
    printf("cc:    vmin=%u vtime=%u eof=%u\n",
           info->vmin, info->vtime, info->eof_pending);
}

int main(void)
{
    char buf[STAT_BUF_SIZE];
    tty_info_t info;

    if (read_proc_stat(buf, sizeof(buf)) < 0) {
        printf("ttyinfo: cannot read /proc/stat\n");
        return 1;
    }

    parse_tty_info(buf, &info);

    printf("TTY tty0\n");
    printf("input:  depth=%u/%u chars=%u\n",
           info.input_depth, info.input_capacity, info.input_chars);
    printf("wake:   char=%u line=%u eof=%u\n",
           info.char_wakeups, info.line_wakeups, info.eof_wakeups);
    printf("output: enq=%u drain=%u full=%u drain-calls=%u\n",
           info.tx_enqueued, info.tx_drained,
           info.tx_full_waits, info.tx_drain_calls);
    print_flags(&info);
    printf("jobctl: fg_pgid=%d read_wait_pid=%d read_wait_state=%d\n",
           info.fg_pgid, info.read_wait_pid, info.read_wait_state);
    printf("signal: ctrl_c=%u delivered=%u missed=%u ctrl_z=%u delivered=%u missed=%u\n",
           info.ctrl_c_seen, info.sigint_delivered, info.sigint_missed,
           info.ctrl_z_seen, info.sigtstp_delivered, info.sigtstp_missed);
    printf("last:   signal=%d pgid=%d delivered=%d\n",
           info.last_signal, info.last_pgid, info.last_delivered);

    return 0;
}
