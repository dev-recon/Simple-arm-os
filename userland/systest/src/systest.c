#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;

static void pass(const char *name)
{
    printf("[OK] %s\n", name);
}

static void fail(const char *name, int value)
{
    printf("[FAIL] %s (%d, errno=%d)\n", name, value, errno);
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

static void test_file_io(void)
{
    const char *path = "/tmp/systest.txt";
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
    const char *path = "/tmp/umask.txt";
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
    fd = open("/tmp/dup2.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
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

    n = read_file("/tmp/dup2.txt", buf, sizeof(buf));
    expect(n == 8 && strcmp(buf, "dup2-ok\n") == 0, "dup2 redirected write", n);
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

static void test_identity(void)
{
    expect(getuid() == 1000, "shell runs as user uid", getuid());
    expect(getgid() == 1000, "shell runs as user gid", getgid());
}

int main(void)
{
    printf("=== syscall smoke tests ===\n");

    test_identity();
    test_file_io();
    test_access_umask();
    test_pipe_dup2();
    test_fork_wait_kill();

    if (failures == 0) {
        printf("systest: all tests passed\n");
        exit(0);
    }

    printf("systest: %d failure(s)\n", failures);
    exit(1);
}
