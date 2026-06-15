#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define COLOR_GREEN "\033[32m"
#define COLOR_RED   "\033[31m"
#define COLOR_RESET "\033[0m"

static int failures = 0;
static volatile int cow_shared_value = 11;

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

static int read_free_mem_kb(unsigned *free_kb)
{
    struct sysinfo_response info;

    if (getsysinfo(&info) < 0)
        return -1;

    *free_kb = info.mem_free_kb;
    return 0;
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
    test_cow_memory();
    test_cow_fork_stress();

    if (failures == 0) {
        printf("systest: all tests passed\n");
        exit(0);
    }

    printf("systest: %d failure(s)\n", failures);
    exit(1);
}
