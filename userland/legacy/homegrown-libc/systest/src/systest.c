/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/legacy/homegrown-libc/systest/src/systest.c
 * Layer: Userland / program
 * Description: ArmOS userspace program or support module.
 */

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>

#define COLOR_GREEN "\033[32m"
#define COLOR_RED   "\033[31m"
#define COLOR_RESET "\033[0m"

static int failures = 0;
static volatile int cow_shared_value = 11;
static volatile int sleep_signal_seen = 0;
static struct sysinfo_response sysinfo_scratch;
static char systest_tmp_root[64];

static const char *tmp_path(const char *name)
{
    static char paths[32][128];
    static int slot = 0;
    char *out = paths[slot++ & 31];

    snprintf(out, 128, "%s/%s", systest_tmp_root, name);
    return out;
}

static void pass(const char *name)
{
    printf(COLOR_GREEN "[OK]" COLOR_RESET " %s\n", name);
}

static void fail(const char *name, int value)
{
    printf(COLOR_RED "[KO]" COLOR_RESET " %s (%d, errno=%d)\n", name, value, errno);
    failures++;
}

static int expect(int cond, const char *name, int value)
{
    if (cond) {
        pass(name);
        return 0;
    }
    fail(name, value);
    return -1;
}

static int read_file(const char *path, char *buf, int size)
{
    int fd;
    int n;

    fd = open(path, O_RDONLY, 0);
    if (fd < 0)
        return -1;

    n = read(fd, buf, size - 1);
    close(fd);

    if (n < 0)
        return -1;

    buf[n] = '\0';
    return n;
}

static int run_command(char *const argv[])
{
    char *const envp[] = { NULL };
    int status = -1;
    int pid = fork();

    if (pid == 0) {
        execve(argv[0], argv, envp);
        exit(127);
    }

    if (pid < 0)
        return -1;

    if (waitpid(pid, &status, 0) != pid)
        return -1;

    return status;
}

static int run_rm1(const char *arg)
{
    char *argv[] = { "/bin/rm", (char *)arg, NULL };
    return run_command(argv);
}

static int run_rm2(const char *opt, const char *arg)
{
    char *argv[] = { "/bin/rm", (char *)opt, (char *)arg, NULL };
    return run_command(argv);
}

static int run_ln2(const char *target, const char *link_name)
{
    char *argv[] = { "/bin/ln", (char *)target, (char *)link_name, NULL };
    return run_command(argv);
}

static int run_ln3(const char *opt, const char *target, const char *link_name)
{
    char *argv[] = { "/bin/ln", (char *)opt, (char *)target, (char *)link_name, NULL };
    return run_command(argv);
}

static void test_file_io(void)
{
    const char *path = tmp_path("systest.txt");
    char buf[64];
    int fd;
    int n;

    unlink(path);

    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (expect(fd >= 0, "open create/trunc", fd) < 0)
        return;

    expect(write(fd, "first\n", 6) == 6, "write binary-safe buffer", 0);
    close(fd);

    n = read_file(path, buf, sizeof(buf));
    expect(n == 6 && strcmp(buf, "first\n") == 0, "read back created file", n);

    fd = open(path, O_WRONLY | O_TRUNC, 0);
    if (expect(fd >= 0, "open existing with O_TRUNC", fd) < 0)
        return;

    expect(write(fd, "second\n", 7) == 7, "write after trunc", 0);
    close(fd);

    n = read_file(path, buf, sizeof(buf));
    expect(n == 7 && strcmp(buf, "second\n") == 0, "O_TRUNC removed old contents", n);

    fd = open(path, O_WRONLY | O_APPEND, 0);
    if (expect(fd >= 0, "open existing with O_APPEND", fd) < 0)
        return;

    expect(write(fd, "third\n", 6) == 6, "write append", 0);
    close(fd);

    n = read_file(path, buf, sizeof(buf));
    expect(n == 13 && strcmp(buf, "second\nthird\n") == 0, "O_APPEND extends file", n);
}

static void test_access_umask(void)
{
    const char *path = tmp_path("umask.txt");
    int old_mask;
    int fd;

    expect(access("/bin/systest", F_OK) == 0, "access existing file", 0);
    expect(access("/bin/nope", F_OK) < 0, "access missing file fails", 0);

    old_mask = umask(077);
    expect(old_mask >= 0, "umask returns previous mask", old_mask);

    unlink(path);
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    expect(fd >= 0, "create file with process umask", fd);
    if (fd >= 0)
        close(fd);

    umask(old_mask);
}

static void test_pipe_dup2(void)
{
    int pipefd[2];
    char buf[32];
    int n;
    int saved_stdout;
    int fd;
    int dup_result;
    int write_result;
    int restore_result;

    if (expect(pipe(pipefd) == 0, "pipe create", 0) < 0)
        return;

    expect(write(pipefd[1], "pipe-ok", 7) == 7, "pipe write", 0);
    n = read(pipefd[0], buf, sizeof(buf) - 1);
    if (n >= 0)
        buf[n] = '\0';
    expect(n == 7 && strcmp(buf, "pipe-ok") == 0, "pipe read", n);
    close(pipefd[0]);
    close(pipefd[1]);

    saved_stdout = dup(STDOUT_FILENO);
    fd = open(tmp_path("dup2.txt"), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (expect(saved_stdout >= 0 && fd >= 0, "dup/open for dup2", fd) < 0)
        return;

    dup_result = dup2(fd, STDOUT_FILENO);
    write_result = write(STDOUT_FILENO, "dup2-ok\n", 8);
    restore_result = dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
    close(fd);

    expect(dup_result == STDOUT_FILENO, "dup2 stdout", dup_result);
    expect(write_result == 8, "dup2 redirected write syscall", write_result);
    expect(restore_result == STDOUT_FILENO, "restore stdout with dup2", restore_result);

    n = read_file(tmp_path("dup2.txt"), buf, sizeof(buf));
    expect(n == 8 && strcmp(buf, "dup2-ok\n") == 0, "dup2 redirected write", n);
}

static void test_fd_access_modes(void)
{
    const char *path = tmp_path("fd-modes.txt");
    char c = 0;
    int fd;

    unlink(path);

    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (expect(fd >= 0, "fd mode open write-only", fd) < 0)
        return;

    expect(write(fd, "x", 1) == 1, "fd mode write to write-only", fd);
    expect(read(fd, &c, 1) < 0, "fd mode read from write-only fails", fd);
    close(fd);

    fd = open(path, O_RDONLY, 0);
    if (expect(fd >= 0, "fd mode open read-only", fd) < 0)
        return;

    expect(read(fd, &c, 1) == 1 && c == 'x', "fd mode read from read-only", c);
    expect(write(fd, "y", 1) < 0, "fd mode write to read-only fails", fd);
    close(fd);
}

static void test_stat_syscalls(void)
{
    struct stat st;
    struct stat fst;
    int fd;

    expect(stat("/bin/systest", &st) == 0, "stat existing executable", 0);
    expect(S_ISREG(st.st_mode), "stat reports regular file", st.st_mode);
    expect(st.st_size > 0, "stat reports file size", (int)st.st_size);
    expect(st.st_blksize > 0, "stat reports IO block size", (int)st.st_blksize);
    expect(st.st_blocks > 0, "stat reports allocated blocks", (int)st.st_blocks);

    fd = open("/bin/systest", O_RDONLY, 0);
    if (expect(fd >= 0, "open executable for fstat", fd) >= 0) {
        expect(fstat(fd, &fst) == 0, "fstat open executable", 0);
        expect(fst.st_size == st.st_size, "fstat size matches stat", (int)fst.st_size);
        expect((fst.st_mode & S_IFMT) == (st.st_mode & S_IFMT),
               "fstat type matches stat", fst.st_mode);
        close(fd);
    }

    expect(stat("/", &st) == 0, "stat root directory", 0);
    expect(S_ISDIR(st.st_mode), "stat reports directory", st.st_mode);
    expect(stat("/bin/does-not-exist", &st) < 0, "stat missing file fails", 0);
}

static void test_chmod_chown_syscalls(void)
{
    const char *path = tmp_path("chmod-chown.txt");
    struct stat st;
    uid_t original_uid = 0;
    int fd;

    unlink(path);
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (expect(fd >= 0, "chmod/chown create test file", fd) < 0)
        return;
    close(fd);

    expect(chmod(path, 0600) == 0, "chmod octal syscall", 0);
    if (expect(stat(path, &st) == 0, "chmod octal stat", 0) == 0)
        expect((st.st_mode & 0777) == 0600, "chmod octal mode visible", st.st_mode & 0777);

    expect(chmod(path, 0755) == 0, "chmod 755 syscall", 0);
    if (expect(stat(path, &st) == 0, "chmod 755 stat", 0) == 0) {
        expect((st.st_mode & 0777) == 0755, "chmod 755 mode visible", st.st_mode & 0777);
        original_uid = st.st_uid;
    }

    expect(chown(path, (uid_t)-1, 789) == 0, "chown gid-only syscall", 0);
    if (expect(stat(path, &st) == 0, "chown gid-only stat", 0) == 0) {
        expect(st.st_gid == 789, "chown gid-only updates gid", st.st_gid);
        expect(st.st_uid == original_uid, "chown gid-only keeps uid", st.st_uid);
    }

    expect(chown(path, 123, 456) == 0, "chown uid/gid syscall", 0);
    if (expect(stat(path, &st) == 0, "chown stat", 0) == 0) {
        expect(st.st_uid == 123, "chown uid visible", st.st_uid);
        expect(st.st_gid == 456, "chown gid visible", st.st_gid);
    }

    unlink(path);
}

static void test_posix_compat_syscalls(void)
{
    const char *path = tmp_path("compat-syscalls.txt");
    struct stat st;
    struct timeval tv;
    struct timezone tz;
    struct termios tio;
    time_t now = 0;
    int fd;
    int dupfd;
    int flags;

    unlink(path);

    fd = creat(path, 0644);
    if (expect(fd >= 0, "creat creates file", fd) >= 0) {
        expect(write(fd, "compat", 6) == 6, "creat fd is writable", fd);
        close(fd);
    }

    expect(lstat(path, &st) == 0, "lstat existing file", 0);
    expect(S_ISREG(st.st_mode), "lstat reports regular file", st.st_mode);

    fd = open(path, O_RDWR, 0);
    if (expect(fd >= 0, "fcntl test open", fd) >= 0) {
        expect(fcntl(fd, F_GETFD, 0) == 0, "fcntl F_GETFD default", fd);
        expect(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, "fcntl F_SETFD cloexec", fd);
        expect((fcntl(fd, F_GETFD, 0) & FD_CLOEXEC) != 0,
               "fcntl F_GETFD observes cloexec", fd);

        flags = fcntl(fd, F_GETFL, 0);
        expect((flags & O_ACCMODE) == O_RDWR, "fcntl F_GETFL access mode", flags);
        expect(fcntl(fd, F_SETFL, flags | O_APPEND) == 0, "fcntl F_SETFL append", flags);
        expect((fcntl(fd, F_GETFL, 0) & O_APPEND) != 0,
               "fcntl F_GETFL observes append", fd);

        dupfd = fcntl(fd, F_DUPFD, 10);
        if (expect(dupfd >= 10, "fcntl F_DUPFD min fd", dupfd) >= 0)
            close(dupfd);

        expect(ioctl(fd, TCGETS, &tio) < 0 && errno == ENOTTY,
               "ioctl TCGETS rejects regular file", errno);
        close(fd);
    }

    expect(ioctl(STDIN_FILENO, TCGETS, &tio) == 0, "ioctl TCGETS accepts tty", 0);
    expect(tcgetattr(STDIN_FILENO, &tio) == 0, "tcgetattr accepts tty", 0);

    expect(time(&now) != (time_t)-1 && now != 0, "time returns timestamp", (int)now);
    expect(gettimeofday(&tv, &tz) == 0, "gettimeofday succeeds", 0);
    expect(tv.tv_sec != 0 && tv.tv_usec < 1000000,
           "gettimeofday reports sane value", (int)tv.tv_usec);

    unlink(path);
}

static void test_ext2_links_and_dirents(void)
{
    const char *path = tmp_path("link-target.txt");
    const char *hard = tmp_path("link-hard.txt");
    const char *sym = tmp_path("link-sym.txt");
    const char *cmd_hard = tmp_path("ln-cmd-hard.txt");
    const char *cmd_sym = tmp_path("ln-cmd-sym.txt");
    struct stat st_path;
    struct stat st_hard;
    struct stat st_sym;
    char buf[64];
    char dents[512];
    int fd;
    int n;
    int saw_dot = 0;
    int saw_dotdot = 0;

    unlink(cmd_sym);
    unlink(cmd_hard);
    unlink(sym);
    unlink(hard);
    unlink(path);

    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (expect(fd >= 0, "link target create", fd) < 0)
        return;
    expect(write(fd, "linked", 6) == 6, "link target write", fd);
    close(fd);

    expect(link(path, hard) == 0, "hard link syscall", 0);
    if (expect(stat(path, &st_path) == 0, "hard link stat original", 0) == 0 &&
        expect(stat(hard, &st_hard) == 0, "hard link stat alias", 0) == 0) {
        expect(st_path.st_ino == st_hard.st_ino, "hard link shares inode", st_hard.st_ino);
        expect(st_path.st_nlink >= 2 && st_hard.st_nlink >= 2,
               "hard link increments nlink", st_hard.st_nlink);
    }

    expect(unlink(path) == 0, "unlink original hard link", 0);
    n = read_file(hard, buf, sizeof(buf));
    expect(n == 6 && strcmp(buf, "linked") == 0,
           "hard link survives original unlink", n);

    expect(symlink(hard, sym) == 0, "symlink syscall", 0);
    memset(buf, 0, sizeof(buf));
    n = readlink(sym, buf, sizeof(buf) - 1);
    if (expect(n == (int)strlen(hard), "readlink returns target length", n) == 0) {
        buf[n] = '\0';
        expect(strcmp(buf, hard) == 0, "readlink target bytes", n);
    }

    if (expect(lstat(sym, &st_sym) == 0, "lstat symlink", 0) == 0)
        expect(S_ISLNK(st_sym.st_mode), "lstat reports symlink", st_sym.st_mode);

    n = read_file(sym, buf, sizeof(buf));
    expect(n == 6 && strcmp(buf, "linked") == 0, "stat/open follows symlink", n);

    expect(run_ln2(hard, cmd_hard) == 0, "ln command hard link", 0);
    n = read_file(cmd_hard, buf, sizeof(buf));
    expect(n == 6 && strcmp(buf, "linked") == 0, "ln hard link readable", n);

    expect(run_ln3("-s", hard, cmd_sym) == 0, "ln -s command symlink", 0);
    memset(buf, 0, sizeof(buf));
    n = readlink(cmd_sym, buf, sizeof(buf) - 1);
    if (expect(n == (int)strlen(hard), "ln -s readlink length", n) == 0) {
        buf[n] = '\0';
        expect(strcmp(buf, hard) == 0, "ln -s readlink target", n);
    }

    fd = open(systest_tmp_root, O_RDONLY | O_DIRECTORY, 0);
    if (expect(fd >= 0, "getdents open /tmp", fd) >= 0) {
        n = getdents(fd, dents, sizeof(dents));
        close(fd);
        if (expect(n > 0, "getdents returns entries", n) == 0) {
            int pos = 0;
            while (pos < n) {
                struct linux_dirent *de = (struct linux_dirent *)(dents + pos);
                if (strcmp(de->d_name, ".") == 0)
                    saw_dot = 1;
                if (strcmp(de->d_name, "..") == 0)
                    saw_dotdot = 1;
                if (de->d_reclen == 0)
                    break;
                pos += de->d_reclen;
            }
            expect(saw_dot, "getdents exposes dot", saw_dot);
            expect(saw_dotdot, "getdents exposes dotdot", saw_dotdot);
        }
    }

    unlink(cmd_sym);
    unlink(cmd_hard);
    unlink(sym);
    unlink(hard);
}

static void test_ext2_write_edges(void)
{
    char buf[64];
    char bigbuf[512];
    struct stat st;
    int fd;
    int n;
    int total;

    unlink(tmp_path("ext2-renamed.txt"));
    unlink(tmp_path("ext2-edge.txt"));
    unlink(tmp_path("ext2-big.bin"));
    rmdir(tmp_path("ext2-edge-dir"));

    expect(mkdir(tmp_path("ext2-edge-dir"), 0755) == 0, "ext2 mkdir edge dir", 0);
    if (expect(stat(tmp_path("ext2-edge-dir"), &st) == 0, "ext2 stat new dir", 0) == 0)
        expect(S_ISDIR(st.st_mode) && st.st_nlink >= 2,
               "ext2 new dir link count", (int)st.st_nlink);

    fd = open(tmp_path("ext2-edge-dir/file.txt"), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (expect(fd >= 0, "ext2 create file in new dir", fd) >= 0) {
        expect(write(fd, "abcdef", 6) == 6, "ext2 write new file", fd);
        close(fd);
    }
    if (expect(stat(tmp_path("ext2-edge-dir/file.txt"), &st) == 0, "ext2 stat new file", 0) == 0)
        expect(S_ISREG(st.st_mode) && st.st_nlink == 1,
               "ext2 new file link count", (int)st.st_nlink);

    expect(rmdir(tmp_path("ext2-edge-dir")) < 0, "ext2 rmdir non-empty fails", 0);
    expect(rename(tmp_path("ext2-edge-dir/file.txt"), tmp_path("ext2-renamed.txt")) == 0,
           "ext2 rename file out of dir", 0);
    expect(rmdir(tmp_path("ext2-edge-dir")) == 0, "ext2 rmdir empty dir", 0);

    fd = open(tmp_path("ext2-renamed.txt"), O_WRONLY | O_TRUNC, 0);
    if (expect(fd >= 0, "ext2 open existing with trunc", fd) >= 0) {
        expect(write(fd, "xy", 2) == 2, "ext2 write after trunc", fd);
        close(fd);
    }

    fd = open(tmp_path("ext2-renamed.txt"), O_WRONLY | O_APPEND, 0);
    if (expect(fd >= 0, "ext2 open existing with append", fd) >= 0) {
        expect(write(fd, "z", 1) == 1, "ext2 append write", fd);
        close(fd);
    }

    n = read_file(tmp_path("ext2-renamed.txt"), buf, sizeof(buf));
    expect(n == 3 && strcmp(buf, "xyz") == 0, "ext2 read truncate+append result", n);

    memset(bigbuf, 'A', sizeof(bigbuf));
    fd = open(tmp_path("ext2-big.bin"), O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (expect(fd >= 0, "ext2 double-indirect create", fd) >= 0) {
        total = 0;
        while (total < 300 * 1024) {
            if (write(fd, bigbuf, sizeof(bigbuf)) != (int)sizeof(bigbuf))
                break;
            total += sizeof(bigbuf);
        }
        expect(total == 300 * 1024, "ext2 double-indirect write", total);
        expect(lseek(fd, 299 * 1024, SEEK_SET) == 299 * 1024,
               "ext2 double-indirect seek", 0);
        memset(buf, 0, sizeof(buf));
        n = read(fd, buf, 16);
        expect(n == 16 && buf[0] == 'A' && buf[15] == 'A',
               "ext2 double-indirect read tail", n);
        close(fd);
    }
    unlink(tmp_path("ext2-big.bin"));

    expect(unlink(tmp_path("ext2-renamed.txt")) == 0, "ext2 unlink renamed file", 0);
    expect(open(tmp_path("ext2-renamed.txt"), O_RDONLY, 0) < 0, "ext2 unlinked file missing", 0);
}

static void test_rm_recursive_utility(void)
{
    struct stat st;
    int fd;

    unlink(tmp_path("rm-dir-link"));
    unlink(tmp_path("rm-tree/sub/file.txt"));
    rmdir(tmp_path("rm-tree/sub"));
    rmdir(tmp_path("rm-tree"));

    expect(mkdir(tmp_path("rm-tree"), 0755) == 0, "rm -r mkdir root", 0);
    expect(mkdir(tmp_path("rm-tree/sub"), 0755) == 0, "rm -r mkdir child", 0);

    fd = open(tmp_path("rm-tree/sub/file.txt"), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (expect(fd >= 0, "rm -r create nested file", fd) >= 0) {
        expect(write(fd, "x", 1) == 1, "rm -r write nested file", fd);
        close(fd);
    }

    expect(run_rm1(tmp_path("rm-tree")) != 0, "rm refuses directory without -r", 0);
    expect(stat(tmp_path("rm-tree/sub/file.txt"), &st) == 0, "rm refusal preserves tree", 0);

    expect(symlink(tmp_path("rm-tree"), tmp_path("rm-dir-link")) == 0, "rm symlink-to-dir setup", 0);
    expect(run_rm2("-rf", tmp_path("rm-dir-link")) == 0, "rm -rf removes symlink to dir only", 0);
    expect(lstat(tmp_path("rm-dir-link"), &st) < 0, "rm removed symlink itself", 0);
    expect(stat(tmp_path("rm-tree/sub/file.txt"), &st) == 0,
           "rm symlink target tree survives", 0);

    expect(run_rm2("-rf", tmp_path("rm-tree")) == 0, "rm -rf removes directory tree", 0);
    expect(stat(tmp_path("rm-tree"), &st) < 0, "rm -rf removed root directory", 0);
}

static void test_fork_wait_kill(void)
{
    int status = -1;
    int pid;
    int waited;

    pid = fork();
    if (pid == 0)
        exit(42);

    if (expect(pid > 0, "fork child", pid) < 0)
        return;

    waited = waitpid(pid, &status, 0);
    expect(waited == pid && status == 42, "waitpid collects exit status", waited);

    pid = fork();
    if (pid == 0) {
        while (1)
            usleep(10000);
    }

    if (expect(pid > 0, "fork kill child", pid) < 0)
        return;

    expect(kill(pid, SIGKILL) == 0, "kill SIGKILL", 0);
    waited = waitpid(pid, &status, 0);
    expect(waited == pid, "waitpid collects killed child", waited);
}

static void test_process_groups(void)
{
    int pids[2] = {-1, -1};
    int pgid = 0;
    int status = -1;
    int reaped = 0;

    for (int i = 0; i < 2; i++) {
        int pid = fork();
        if (pid == 0) {
            while (1)
                usleep(50000);
        }

        if (pid < 0)
            break;

        if (i == 0)
            pgid = pid;
        pids[i] = pid;
        setpgid(pid, pgid);
    }

    if (expect(pids[0] > 0 && pids[1] > 0, "process group fork children", pids[1]) < 0)
        return;

    expect(kill(-pgid, SIGKILL) == 0, "process group kill -pgid", pgid);

    for (int i = 0; i < 2; i++) {
        status = -1;
        if (waitpid(pids[i], &status, 0) == pids[i])
            reaped++;
    }

    expect(reaped == 2, "process group reaps killed children", reaped);
}

static void test_waitpid_process_group(void)
{
    int pids[2] = {-1, -1};
    int pgid = 0;
    int status = -1;
    int waited;
    int reaped = 0;

    for (int i = 0; i < 2; i++) {
        int pid = fork();
        if (pid == 0) {
            if (i == 0) {
                usleep(50000); /* Let the parent set the target process group. */
                exit(61);
            }
            while (1)
                usleep(50000);
        }

        if (pid < 0)
            break;

        if (i == 0)
            pgid = pid;
        pids[i] = pid;
        setpgid(pid, pgid);
    }

    if (expect(pids[0] > 0 && pids[1] > 0, "waitpid -pgid fork children", pids[1]) < 0)
        return;

    waited = waitpid(-pgid, &status, 0);
    expect(waited == pids[0] && status == 61, "waitpid -pgid reaps group child", waited);

    expect(kill(-pgid, SIGKILL) == 0, "waitpid -pgid kill remaining group", pgid);
    for (int i = 0; i < 2; i++) {
        if (pids[i] == waited)
            continue;
        status = -1;
        if (waitpid(pids[i], &status, 0) == pids[i])
            reaped++;
    }

    expect(reaped == 1, "waitpid -pgid reaps remaining child", reaped);
}

static void test_waitpid_wuntraced_continue(void)
{
    int pid;
    int status = -1;
    int waited;

    pid = fork();
    if (pid == 0) {
        while (1)
            usleep(50000);
    }

    if (expect(pid > 0, "WUNTRACED fork child", pid) < 0)
        return;

    setpgid(pid, pid);
    expect(kill(pid, SIGSTOP) == 0, "kill SIGSTOP", pid);
    waited = waitpid(-pid, &status, WUNTRACED);
    expect(waited == pid, "waitpid WUNTRACED reports stopped child", waited);
    expect(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP,
           "waitpid stopped status encodes SIGSTOP", status);

    expect(kill(pid, SIGCONT) == 0, "kill SIGCONT stopped child", pid);
    expect(kill(pid, SIGKILL) == 0, "kill SIGKILL continued child", pid);
    waited = waitpid(pid, &status, 0);
    expect(waited == pid, "waitpid reaps continued killed child", waited);
}

static void test_waitpid_group_stop_reports_all(void)
{
    int pids[2] = {-1, -1};
    int pgid = 0;
    int stopped = 0;
    int reaped = 0;
    int status = -1;

    for (int i = 0; i < 2; i++) {
        int pid = fork();
        if (pid == 0) {
            while (1)
                usleep(50000);
        }

        if (pid < 0)
            break;

        if (i == 0)
            pgid = pid;
        pids[i] = pid;
        setpgid(pid, pgid);
    }

    if (expect(pids[0] > 0 && pids[1] > 0, "WUNTRACED group fork children", pids[1]) < 0)
        return;

    expect(kill(-pgid, SIGSTOP) == 0, "WUNTRACED group SIGSTOP", pgid);
    while (stopped < 2) {
        int waited = waitpid(-pgid, &status, WUNTRACED);
        if (waited <= 0)
            break;
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
            stopped++;
    }
    expect(stopped == 2, "WUNTRACED group reports all stopped children", stopped);

    expect(kill(-pgid, SIGCONT) == 0, "WUNTRACED group SIGCONT", pgid);
    expect(kill(-pgid, SIGKILL) == 0, "WUNTRACED group cleanup kill", pgid);

    for (int i = 0; i < 2; i++) {
        status = -1;
        if (waitpid(pids[i], &status, 0) == pids[i])
            reaped++;
    }
    expect(reaped == 2, "WUNTRACED group cleanup reap", reaped);
}

static void test_sleep_survives_stop_continue(void)
{
    int pid;
    int status = -1;
    int waited;

    pid = fork();
    if (pid == 0) {
        sleep(8);
        exit(77);
    }

    if (expect(pid > 0, "sleep stop/continue fork child", pid) < 0)
        return;

    setpgid(pid, pid);
    usleep(1000000);
    expect(kill(pid, SIGSTOP) == 0, "sleep stop/continue SIGSTOP", pid);
    waited = waitpid(-pid, &status, WUNTRACED);
    expect(waited == pid && WIFSTOPPED(status), "sleep stop/continue wait stopped", waited);

    expect(kill(pid, SIGCONT) == 0, "sleep stop/continue SIGCONT", pid);
    usleep(500000);
    waited = waitpid(pid, &status, WNOHANG);
    expect(waited == 0, "sleep continues after SIGCONT", waited);

    expect(kill(pid, SIGKILL) == 0, "sleep stop/continue cleanup kill", pid);
    waited = waitpid(pid, &status, 0);
    expect(waited == pid, "sleep stop/continue cleanup reap", waited);
}

static void systest_sleep_signal_handler(int sig)
{
    (void)sig;
    sleep_signal_seen = 1;
}

static void test_nanosleep_signal_interrupt(void)
{
    struct timespec req;
    struct timespec rem;
    int parent_pid;
    int pid;
    int status = -1;
    int rc;

    sleep_signal_seen = 0;
    signal(SIGUSR1, systest_sleep_signal_handler);
    parent_pid = getpid();

    pid = fork();
    if (pid == 0) {
        usleep(200000);
        kill(parent_pid, SIGUSR1);
        exit(0);
    }

    if (expect(pid > 0, "nanosleep interrupt fork child", pid) < 0) {
        signal(SIGUSR1, SIG_DFL);
        return;
    }

    req.tv_sec = 2;
    req.tv_nsec = 0;
    rem.tv_sec = 0;
    rem.tv_nsec = 0;
    errno = 0;
    rc = nanosleep(&req, &rem);

    expect(rc < 0 && errno == EINTR, "nanosleep interrupted by signal", rc);
    expect(sleep_signal_seen == 1, "nanosleep signal handler ran", sleep_signal_seen);
    expect(rem.tv_sec > 0 || rem.tv_nsec > 0, "nanosleep reports remaining time", (int)rem.tv_sec);
    expect(waitpid(pid, &status, 0) == pid && status == 0, "nanosleep signal child reaped", status);
    signal(SIGUSR1, SIG_DFL);
}

static void test_cow_memory(void)
{
    int pid;
    int status = -1;
    int waited;
    unsigned char *heap;
    volatile unsigned char stack_area[8192];

    cow_shared_value = 11;
    pid = fork();
    if (pid == 0) {
        cow_shared_value = 33;
        exit(cow_shared_value == 33 ? 0 : 1);
    }

    if (expect(pid > 0, "COW fork child writer", pid) < 0)
        return;

    waited = waitpid(pid, &status, 0);
    expect(waited == pid && status == 0, "COW child writes private page", waited);
    expect(cow_shared_value == 11, "COW parent value unchanged", cow_shared_value);

    cow_shared_value = 11;
    pid = fork();
    if (pid == 0) {
        usleep(20000);
        exit(cow_shared_value == 11 ? 0 : 1);
    }

    if (expect(pid > 0, "COW fork parent writer", pid) < 0)
        return;

    cow_shared_value = 44;
    waited = waitpid(pid, &status, 0);
    expect(waited == pid && status == 0, "COW parent writes private page", waited);
    expect(cow_shared_value == 44, "COW parent keeps own write", cow_shared_value);

    heap = malloc(8192);
    if (expect(heap != NULL, "COW heap allocation", 0) < 0)
        return;

    heap[0] = 0x11;
    heap[4095] = 0x22;
    heap[4096] = 0x33;
    heap[8191] = 0x44;

    pid = fork();
    if (pid == 0) {
        heap[0] = 0xAA;
        heap[4096] = 0xBB;
        exit(heap[0] == 0xAA && heap[4096] == 0xBB ? 0 : 1);
    }

    if (expect(pid > 0, "COW heap child writer", pid) >= 0) {
        waited = waitpid(pid, &status, 0);
        expect(waited == pid && status == 0, "COW heap child writes private pages", waited);
        expect(heap[0] == 0x11 && heap[4095] == 0x22 &&
               heap[4096] == 0x33 && heap[8191] == 0x44,
               "COW heap parent unchanged", heap[0]);
    }

    heap[0] = 0x11;
    heap[4096] = 0x33;

    pid = fork();
    if (pid == 0) {
        usleep(20000);
        exit(heap[0] == 0x11 && heap[4096] == 0x33 ? 0 : 1);
    }

    if (expect(pid > 0, "COW heap parent writer", pid) >= 0) {
        heap[0] = 0xCC;
        heap[4096] = 0xDD;
        waited = waitpid(pid, &status, 0);
        expect(waited == pid && status == 0, "COW heap child unchanged", waited);
        expect(heap[0] == 0xCC && heap[4096] == 0xDD,
               "COW heap parent keeps own writes", heap[0]);
    }

    free(heap);

    stack_area[0] = 0x12;
    stack_area[4095] = 0x23;
    stack_area[4096] = 0x34;
    stack_area[8191] = 0x45;

    pid = fork();
    if (pid == 0) {
        stack_area[0] = 0xAB;
        stack_area[4096] = 0xBC;
        exit(stack_area[0] == 0xAB && stack_area[4096] == 0xBC ? 0 : 1);
    }

    if (expect(pid > 0, "COW stack child writer", pid) >= 0) {
        waited = waitpid(pid, &status, 0);
        expect(waited == pid && status == 0, "COW stack child writes private pages", waited);
        expect(stack_area[0] == 0x12 && stack_area[4095] == 0x23 &&
               stack_area[4096] == 0x34 && stack_area[8191] == 0x45,
               "COW stack parent unchanged", stack_area[0]);
    }

    stack_area[0] = 0x12;
    stack_area[4096] = 0x34;

    pid = fork();
    if (pid == 0) {
        usleep(20000);
        exit(stack_area[0] == 0x12 && stack_area[4096] == 0x34 ? 0 : 1);
    }

    if (expect(pid > 0, "COW stack parent writer", pid) >= 0) {
        stack_area[0] = 0xCD;
        stack_area[4096] = 0xDE;
        waited = waitpid(pid, &status, 0);
        expect(waited == pid && status == 0, "COW stack child unchanged", waited);
        expect(stack_area[0] == 0xCD && stack_area[4096] == 0xDE,
               "COW stack parent keeps own writes", stack_area[0]);
    }
}

static void test_shared_memory(void)
{
    char name[32];
    int id;
    int pid;
    int status = -1;
    int waited;
    volatile int *shared;

    snprintf(name, sizeof(name), "systest-shm-%d", getpid());
    shm_unlink(name);
    id = shm_open(name, 4096, SHM_O_CREAT | SHM_O_EXCL);
    if (expect(id >= 0, "shm create", id) < 0)
        return;

    shared = (volatile int *)shm_map(id, NULL, SHM_RDWR);
    if (expect(shared != NULL, "shm map parent", id) < 0) {
        shm_unlink(name);
        return;
    }

    shared[0] = 1234;
    shared[1] = 0;

    pid = fork();
    if (pid == 0) {
        if (shared[0] != 1234)
            exit(2);
        shared[0] = 5678;
        shared[1] = 42;
        exit(0);
    }

    if (expect(pid > 0, "shm fork child", pid) < 0) {
        shm_unmap((void *)shared, 4096);
        shm_unlink(name);
        return;
    }

    waited = waitpid(pid, &status, 0);
    expect(waited == pid && status == 0, "shm child sees parent data", waited);
    expect(shared[0] == 5678 && shared[1] == 42, "shm parent sees child writes", shared[0]);
    expect(shm_unmap((void *)shared, 4096) == 0, "shm unmap parent", 0);
    expect(shm_unlink(name) == 0, "shm unlink", 0);
}

static int read_free_mem_kb(unsigned *free_kb)
{
    if (getsysinfo(&sysinfo_scratch) < 0)
        return -1;

    *free_kb = sysinfo_scratch.mem_free_kb;
    return 0;
}

static int read_self_mem_kb(unsigned *heap_kb, unsigned *rss_kb, unsigned *pf)
{
    int self = getpid();

    if (getsysinfo(&sysinfo_scratch) < 0)
        return -1;

    for (int i = 0; i < sysinfo_scratch.proc_count; i++) {
        if (sysinfo_scratch.procs[i].pid == self) {
            if (heap_kb)
                *heap_kb = sysinfo_scratch.procs[i].heap_kb;
            if (rss_kb)
                *rss_kb = sysinfo_scratch.procs[i].rss_kb;
            if (pf)
                *pf = sysinfo_scratch.procs[i].page_faults;
            return 0;
        }
    }

    return -1;
}

static void touch_all_pages(unsigned char *ptr, size_t size, unsigned char seed)
{
    for (size_t off = 0; off < size; off += 4096)
        ptr[off] = (unsigned char)(seed + (off >> 12));
    ptr[size - 1] = (unsigned char)(seed ^ 0x5a);
}

static int check_all_pages(unsigned char *ptr, size_t size, unsigned char seed)
{
    for (size_t off = 0; off < size; off += 4096) {
        if (ptr[off] != (unsigned char)(seed + (off >> 12)))
            return 0;
    }
    return ptr[size - 1] == (unsigned char)(seed ^ 0x5a);
}

static void test_malloc_free_stress(void)
{
    enum { BLOCKS = 5 };
    static const size_t sizes[BLOCKS] = { 4096, 8192, 32768, 65536, 131072 };
    unsigned char *blocks[BLOCKS];
    unsigned heap_before = 0;
    unsigned heap_after_alloc = 0;
    unsigned heap_after_reuse = 0;
    unsigned heap_after_free = 0;
    unsigned rss_after_alloc = 0;
    unsigned pf_before = 0;
    unsigned pf_after = 0;
    int ok = 1;

    for (int i = 0; i < BLOCKS; i++)
        blocks[i] = NULL;

    expect(read_self_mem_kb(&heap_before, NULL, &pf_before) == 0,
           "malloc stress baseline stats", 0);

    for (int i = 0; i < BLOCKS; i++) {
        blocks[i] = malloc(sizes[i]);
        if (!blocks[i]) {
            ok = 0;
            break;
        }
        touch_all_pages(blocks[i], sizes[i], (unsigned char)(0x20 + i * 7));
    }

    expect(ok, "malloc stress multi-page allocations", ok);
    if (!ok)
        goto cleanup;

    for (int i = 0; i < BLOCKS; i++) {
        if (!check_all_pages(blocks[i], sizes[i], (unsigned char)(0x20 + i * 7)))
            ok = 0;
    }
    expect(ok, "malloc stress page contents intact", ok);

    expect(read_self_mem_kb(&heap_after_alloc, &rss_after_alloc, &pf_after) == 0,
           "malloc stress sysinfo after alloc", 0);
    expect(heap_after_alloc >= heap_before + 128,
           "malloc stress heap visible in ps data", (int)(heap_after_alloc - heap_before));
    expect(rss_after_alloc >= heap_after_alloc,
           "malloc stress rss covers heap", (int)rss_after_alloc);
    expect(pf_after >= pf_before,
           "malloc stress page faults stable", (int)(pf_after - pf_before));

    free(blocks[1]);
    blocks[1] = NULL;
    free(blocks[3]);
    blocks[3] = NULL;

    blocks[1] = malloc(12288);
    blocks[3] = malloc(49152);
    ok = blocks[1] && blocks[3];
    if (ok) {
        touch_all_pages(blocks[1], 12288, 0x71);
        touch_all_pages(blocks[3], 49152, 0x91);
        ok = check_all_pages(blocks[1], 12288, 0x71) &&
             check_all_pages(blocks[3], 49152, 0x91);
    }
    expect(ok, "malloc stress free/reuse blocks", ok);

    expect(read_self_mem_kb(&heap_after_reuse, NULL, NULL) == 0,
           "malloc stress sysinfo after reuse", 0);
    expect(heap_after_reuse >= heap_after_alloc,
           "malloc stress heap stays mapped while blocks live", (int)heap_after_reuse);

cleanup:
    for (int i = 0; i < BLOCKS; i++) {
        if (blocks[i])
            free(blocks[i]);
    }

    if (heap_after_alloc > heap_before &&
        expect(read_self_mem_kb(&heap_after_free, NULL, NULL) == 0,
               "malloc stress sysinfo after free", 0) == 0) {
        int heap_delta = (int)heap_after_free - (int)heap_before;
        expect(heap_after_free <= heap_before,
               "malloc stress terminal free shrinks heap",
               heap_delta);
    }
}

static void test_cow_fork_stress(void)
{
    enum { STRESS_ITERS = 64 };
    unsigned char *heap;
    volatile unsigned char stack_area[12288];
    unsigned before_kb = 0;
    unsigned after_kb = 0;
    int loop_ok = 1;
    int leak_kb;
    int pid;
    int status;
    int waited;

    heap = malloc(16384);
    if (expect(heap != NULL, "COW stress heap allocation", 0) < 0)
        return;

    heap[0] = 0x10;
    heap[4096] = 0x20;
    heap[8192] = 0x30;
    heap[12288] = 0x40;
    stack_area[0] = 0x50;
    stack_area[4096] = 0x60;
    stack_area[8192] = 0x70;

    if (expect(read_free_mem_kb(&before_kb) == 0, "COW stress baseline memory", 0) < 0) {
        free(heap);
        return;
    }

    for (int i = 0; i < STRESS_ITERS; i++) {
        status = -1;
        pid = fork();
        if (pid == 0) {
            heap[0] = (unsigned char)(0x80 + (i & 0x3F));
            heap[8192] = (unsigned char)(0x40 + (i & 0x3F));
            stack_area[0] = (unsigned char)(0x20 + (i & 0x3F));
            stack_area[8192] = (unsigned char)(0x10 + (i & 0x3F));
            exit(heap[0] != 0 && heap[8192] != 0 &&
                 stack_area[0] != 0 && stack_area[8192] != 0 ? 0 : 1);
        }

        if (pid <= 0) {
            loop_ok = 0;
            break;
        }

        heap[4096] = (unsigned char)(0xA0 + (i & 0x1F));
        heap[12288] = (unsigned char)(0xB0 + (i & 0x1F));
        stack_area[4096] = (unsigned char)(0xC0 + (i & 0x1F));

        waited = waitpid(pid, &status, 0);
        if (waited != pid || status != 0) {
            loop_ok = 0;
            break;
        }
    }

    expect(loop_ok, "COW stress fork/write/wait loop", loop_ok);
    expect(read_free_mem_kb(&after_kb) == 0, "COW stress final memory", 0);
    leak_kb = before_kb > after_kb ? (int)(before_kb - after_kb) : 0;
    expect(leak_kb <= 512, "COW stress no page-table leak", leak_kb);

    free(heap);
}

static void test_asid_churn(void)
{
    enum { ASID_ITERS = 280 };
    int loop_ok = 1;
    int pid;
    int status;
    int waited;

    for (int i = 0; i < ASID_ITERS; i++) {
        status = -1;
        pid = fork();
        if (pid == 0)
            exit(i & 0x7f);

        if (pid <= 0) {
            loop_ok = 0;
            break;
        }

        waited = waitpid(pid, &status, 0);
        if (waited != pid || status != (i & 0x7f)) {
            loop_ok = 0;
            break;
        }
    }

    expect(loop_ok, "ASID churn over 255 forks", loop_ok);
}

static void test_asid_live_saturation(void)
{
    enum { LIVE_LIMIT = 270 };
    int pids[LIVE_LIMIT];
    int count = 0;
    int reaped = 0;
    int pid;
    int status;

    for (int i = 0; i < LIVE_LIMIT; i++)
        pids[i] = -1;

    for (int i = 0; i < LIVE_LIMIT; i++) {
        pid = fork();
        if (pid == 0) {
            while (1)
                usleep(50000);
        }

        if (pid < 0)
            break;

        pids[count++] = pid;
    }

    expect(count == LIVE_LIMIT, "ASID generation rollover creates full live set", count);

    for (int i = 0; i < count; i++)
        kill(pids[i], SIGKILL);

    for (int i = 0; i < count; i++) {
        status = -1;
        if (waitpid(pids[i], &status, 0) == pids[i])
            reaped++;
    }

    expect(reaped == count, "ASID live saturation reaps children", reaped);
}

static void test_lifecycle_exec_fail_loop(void)
{
    enum { ITERS = 32 };
    int ok = 1;

    for (int i = 0; i < ITERS; i++) {
        int status = -1;
        int pid = fork();

        if (pid == 0) {
            char *argv[] = { "missing-command", NULL };
            execve("/bin/missing-command", argv, NULL);
            exit(90 + (i & 7));
        }

        if (pid <= 0) {
            ok = 0;
            break;
        }

        if (waitpid(pid, &status, 0) != pid || status != 90 + (i & 7)) {
            ok = 0;
            break;
        }
    }

    expect(ok, "lifecycle repeated exec failure is reaped", ok);
}

static void test_lifecycle_wnohang_kill(void)
{
    int status = -1;
    int pid = fork();

    if (pid == 0) {
        while (1)
            usleep(50000);
    }

    if (expect(pid > 0, "lifecycle fork live child", pid) < 0)
        return;

    expect(waitpid(pid, &status, WNOHANG) == 0, "waitpid WNOHANG leaves live child", status);
    expect(kill(pid, SIGKILL) == 0, "lifecycle kill live child", pid);
    expect(waitpid(pid, &status, 0) == pid, "lifecycle reap killed child", status);
}

static void test_lifecycle_orphan_reaper(void)
{
    enum { ITERS = 8 };
    int ok = 1;

    for (int i = 0; i < ITERS; i++) {
        int status = -1;
        int pid = fork();

        if (pid == 0) {
            int grandchild = fork();
            if (grandchild == 0) {
                usleep(20000);
                exit(40 + i);
            }
            exit(grandchild > 0 ? 30 + i : 1);
        }

        if (pid <= 0) {
            ok = 0;
            break;
        }

        if (waitpid(pid, &status, 0) != pid || status != 30 + i) {
            ok = 0;
            break;
        }
    }

    usleep(200000);
    expect(ok, "lifecycle orphan children delegated to init", ok);
}

static void test_identity(void)
{
    expect(getuid() == 1000, "shell runs as user uid", getuid());
    expect(getgid() == 1000, "shell runs as user gid", getgid());
}

static void test_terminal_process_group(void)
{
    int old_pgrp = tcgetpgrp(STDIN_FILENO);
    int self_pgrp = getpgrp();
    int current;

    if (expect(old_pgrp >= 0, "tcgetpgrp returns foreground group", old_pgrp) < 0)
        return;

    if (expect(self_pgrp > 0, "getpgrp returns process group", self_pgrp) < 0)
        return;

    expect(tcsetpgrp(STDIN_FILENO, self_pgrp) == 0, "tcsetpgrp sets foreground group", self_pgrp);
    current = tcgetpgrp(STDIN_FILENO);
    expect(current == self_pgrp, "tcgetpgrp observes tcsetpgrp", current);

    errno = 0;
    expect(tcgetpgrp(99) < 0 && errno == ENOTTY, "tcgetpgrp rejects non-tty fd", errno);
    errno = 0;
    expect(tcsetpgrp(99, self_pgrp) < 0 && errno == ENOTTY, "tcsetpgrp rejects non-tty fd", errno);

    if (old_pgrp >= 0)
        tcsetpgrp(STDIN_FILENO, old_pgrp);
}

static void test_process_session_info(void)
{
    int self = getpid();
    int found = 0;

    if (expect(getsysinfo(&sysinfo_scratch) >= 0, "sysinfo session query", 0) < 0)
        return;

    for (int i = 0; i < sysinfo_scratch.proc_count; i++) {
        if (sysinfo_scratch.procs[i].pid == self) {
            found = 1;
            expect(sysinfo_scratch.procs[i].sid > 0, "sysinfo reports process sid",
                   sysinfo_scratch.procs[i].sid);
            expect(sysinfo_scratch.procs[i].tty == 0, "sysinfo reports controlling tty",
                   sysinfo_scratch.procs[i].tty);
            break;
        }
    }

    expect(found, "sysinfo contains current process", self);
}

int main(void)
{
    printf("=== syscall smoke tests ===\n");
    snprintf(systest_tmp_root, sizeof(systest_tmp_root), "/tmp/systest-%d", getpid());
    run_rm2("-rf", systest_tmp_root);
    mkdir(systest_tmp_root, 0755);

    test_identity();
    test_terminal_process_group();
    test_process_session_info();
    test_file_io();
    test_access_umask();
    test_pipe_dup2();
    test_fd_access_modes();
    test_stat_syscalls();
    test_chmod_chown_syscalls();
    test_posix_compat_syscalls();
    test_ext2_links_and_dirents();
    test_ext2_write_edges();
    test_rm_recursive_utility();
    test_fork_wait_kill();
    test_process_groups();
    test_waitpid_process_group();
    test_waitpid_wuntraced_continue();
    test_waitpid_group_stop_reports_all();
    test_sleep_survives_stop_continue();
    test_nanosleep_signal_interrupt();
    test_malloc_free_stress();
    test_cow_memory();
    test_shared_memory();
    test_cow_fork_stress();
    test_asid_churn();
    test_asid_live_saturation();
    test_lifecycle_exec_fail_loop();
    test_lifecycle_wnohang_kill();
    test_lifecycle_orphan_reaper();

    if (failures == 0) {
        run_rm2("-rf", systest_tmp_root);
        printf("systest: all tests passed\n");
        exit(0);
    }

    run_rm2("-rf", systest_tmp_root);
    printf("systest: %d failure(s)\n", failures);
    exit(1);
}
