#include <kernel/syscalls.h>
#include <kernel/process.h>
#include <kernel/memory.h>
#include <kernel/vfs.h>
#include <kernel/kernel.h>
#include <kernel/string.h>
#include <kernel/task.h>
#include <kernel/userspace.h>
#include <kernel/kprintf.h>
#include <kernel/file.h>
#include <kernel/timer.h>
#include <kernel/ext2.h>

#define PIPE_BUF_SIZE 4096

struct pipe_buffer {
    char data[PIPE_BUF_SIZE];
    size_t read_pos;
    size_t write_pos;
    size_t count;           /* Nombre d'octets dans le buffer */
    int readers;            /* Nombre de lecteurs */
    int writers;            /* Nombre d'écrivains */
    int closed_read;        /* Côté lecture fermé */
    int closed_write;       /* Côté écriture fermé */
};

struct pipe_inode_info {
    struct pipe_buffer *buffer;
};

ssize_t pipe_read(file_t* file, void* buf, size_t count);
ssize_t pipe_write(file_t* file, const void* buf, size_t count);
int pipe_close(file_t* file);

static file_operations_t pipe_read_fops = {
    .read = pipe_read,
    .close = pipe_close,
};

static file_operations_t pipe_write_fops = {
    .write = pipe_write,
    .close = pipe_close,
};

extern char* resolve_path(const char* path);
extern inode_operations_t ext2_inode_ops;

static int pipe_wait_interruptible(void)
{
    if (!current_task)
        return -EINTR;

    task_set_interruptible(current_task);
    current_task->wakeup_time = get_system_ticks() + 1;
    yield();
    current_task->wakeup_time = 0;

    if (has_pending_signals(current_task))
        return -EINTR;

    return 0;
}

bool can_read(file_t* file) {
    int access_mode;

    if (!file) return false;
    access_mode = file->flags & O_ACCMODE;
    return access_mode == O_RDONLY || access_mode == O_RDWR;
}

bool can_write(file_t* file) {
    int access_mode;

    if (!file) return false;
    access_mode = file->flags & O_ACCMODE;
    return access_mode == O_WRONLY || access_mode == O_RDWR;
}

/* Lecture depuis un pipe */
ssize_t pipe_read(file_t* file, void* buf, size_t count) {
    struct pipe_inode_info *pipe = file->private_data;
    struct pipe_buffer *buffer = pipe->buffer;
    char *user_buf = (char*)buf;
    size_t bytes_read = 0;
    uint32_t irq_flags;

    //KDEBUG("ENTERING READING FROM PIPE\n");
    //KDEBUG("file->flags = 0x%08X\n", file->flags);

    /* Vérifier que c'est ouvert en lecture */
    if (!can_read(file)) {
        return -EBADF;
    }

    while (1) {
        irq_flags = disable_interrupts_save();

        /* Si pas de données et plus d'écrivains -> EOF */
        if (buffer->count == 0 && (buffer->writers == 0 || buffer->closed_write)) {
            restore_interrupts(irq_flags);
            return 0;  /* EOF */
        }

        /* Lire les données disponibles */
        while (bytes_read < count && buffer->count > 0) {
            user_buf[bytes_read] = buffer->data[buffer->read_pos];
            buffer->read_pos = (buffer->read_pos + 1) % PIPE_BUF_SIZE;
            buffer->count--;
            bytes_read++;
        }

        restore_interrupts(irq_flags);

        if (bytes_read > 0)
            return bytes_read;

        if (pipe_wait_interruptible() < 0)
            return -EINTR;
    }
}

/* Écriture vers un pipe */
ssize_t pipe_write(file_t* file, const void* buf, size_t count) {
    struct pipe_inode_info *pipe = file->private_data;
    struct pipe_buffer *buffer = pipe->buffer;
    const char *user_buf = (const char*)buf;
    size_t bytes_written = 0;
    uint32_t irq_flags;
    

    /* Vérifier que c'est ouvert en écriture */
    if (!can_write(file)) {
        return -EBADF;
    }
    
    while (bytes_written < count) {
        irq_flags = disable_interrupts_save();

        /* Si pas de lecteurs -> SIGPIPE */
        if (buffer->readers == 0 || buffer->closed_read) {
            restore_interrupts(irq_flags);
            return bytes_written > 0 ? (ssize_t)bytes_written : -EPIPE;
        }

        //KDEBUG("WRITING TO PIPE\n");

        /* Écrire tant qu'il y a de la place */
        while (bytes_written < count && buffer->count < PIPE_BUF_SIZE) {
            buffer->data[buffer->write_pos] = user_buf[bytes_written];
            buffer->write_pos = (buffer->write_pos + 1) % PIPE_BUF_SIZE;
            buffer->count++;
            bytes_written++;
        }

        restore_interrupts(irq_flags);

        if (bytes_written >= count)
            return bytes_written;

        if (pipe_wait_interruptible() < 0)
            return bytes_written > 0 ? (ssize_t)bytes_written : -EINTR;
    }

    //KDEBUG("DATA WROTE TO PIPE\n");
    return bytes_written;
}

int pipe_close(file_t* file) {
    struct pipe_inode_info *pipe = file->private_data;
    struct pipe_buffer *buffer = pipe->buffer;
    
    //KDEBUG("CLOSING PIPE\n");

    /* Déterminer si c'était un lecteur ou écrivain */
    int access_mode = file->flags & O_ACCMODE;

    if (access_mode == O_RDONLY || access_mode == O_RDWR) {
        buffer->readers--;
        if (buffer->readers == 0) {
            buffer->closed_read = 1;
        }
    }
    
    if (access_mode == O_WRONLY || access_mode == O_RDWR) {
        buffer->writers--;
        if (buffer->writers == 0) {
            buffer->closed_write = 1;
        }
    }
    
    /* Libérer si plus personne n'utilise le pipe */
    if (buffer->readers == 0 && buffer->writers == 0) {
        //KDEBUG("NO MORE USERS OF THIS PIPE. Freeing it.\n");
        kfree(buffer);
    }
    
    kfree(pipe);
    //KDEBUG("PIPE CLOSED\n");

    return 0;
}

int sys_pipe(int pipefd[2])
{
    int fd_read, fd_write;
    file_t *read_file, *write_file;
    struct pipe_buffer *buffer;
    struct pipe_inode_info *read_pipe, *write_pipe;
    inode_t *inode;
    int fds[2];
    task_t *task = current_task;
    
    /* Vérifier le pointeur utilisateur */
    if (!pipefd || !task || !task->process) {
        return -EFAULT;
    }
    
    /* Allouer deux descripteurs de fichiers */
    fd_read = allocate_fd(task);
    if (fd_read < 0) return fd_read;

    task->process->files[fd_read] = (file_t *)1;   //FIX ME -> Set to a non NULL value
    task->process->fd_flags[fd_read] = 0;
    
    fd_write = allocate_fd(task);
    if (fd_write < 0) {
        free_fd(task, fd_read);
        return fd_write;
    }
    
    /* Créer le buffer du pipe */
    buffer = kzalloc(sizeof(struct pipe_buffer));
    if (!buffer) {
        free_fd(task, fd_read);
        free_fd(task, fd_write);
        return -ENOMEM;
    }
    
    /* Initialiser le buffer */
    buffer->readers = 1;
    buffer->writers = 1;
    buffer->read_pos = 0;
    buffer->write_pos = 0;
    buffer->count = 0;
    buffer->closed_read = 0;
    buffer->closed_write = 0;
    
    /* Créer l'inode pipe */
    inode = create_inode();
    if (!inode) {
        kfree(buffer);
        free_fd(task, fd_read);
        free_fd(task, fd_write);
        return -ENOMEM;
    }
    
    inode->mode = S_IFIFO | 0600;
    
    /* Créer les structures pipe_inode_info */
    read_pipe = kmalloc(sizeof(struct pipe_inode_info));
    write_pipe = kmalloc(sizeof(struct pipe_inode_info));
    if (!read_pipe || !write_pipe) {
        kfree(buffer);
        kfree(read_pipe);
        kfree(write_pipe);
        put_inode(inode);
        free_fd(task, fd_read);
        free_fd(task, fd_write);
        return -ENOMEM;
    }
    
    read_pipe->buffer = buffer;
    write_pipe->buffer = buffer;
    
    /* Créer les fichiers */
    read_file = create_file();
    write_file = create_file();
    if (!read_file || !write_file) {
        goto cleanup;
    }
    
    /* Configurer le fichier de lecture */
    strcpy(read_file->name, "pipe:[read]");
    read_file->pos = 0;
    read_file->inode = inode;
    read_file->offset = 0;
    read_file->flags = O_RDONLY;        /* ← Utilise le champ flags */
    read_file->ref_count = 1;
    read_file->f_op = &pipe_read_fops;
    read_file->private_data = read_pipe;
    
    /* Configurer le fichier d'écriture */
    strcpy(write_file->name, "pipe:[write]");
    write_file->pos = 0;
    write_file->inode = inode;
    inode->ref_count++;
    write_file->offset = 0;
    write_file->flags = O_WRONLY;       /* ← Utilise le champ flags */
    write_file->ref_count = 1;
    write_file->f_op = &pipe_write_fops;
    write_file->private_data = write_pipe;
    
    /* Associer aux descripteurs */
    task->process->files[fd_read] = read_file;
    task->process->files[fd_write] = write_file;
    task->process->fd_flags[fd_read] = 0;
    task->process->fd_flags[fd_write] = 0;
    
    /* Préparer les fd pour l'userspace */
    fds[0] = fd_read;
    fds[1] = fd_write;
    
    /* Copier vers l'userspace */
    if (copy_to_user(pipefd, fds, 2 * sizeof(int)) != 0) {
        sys_close(fd_read);
        sys_close(fd_write);
        return -EFAULT;
    }
    
    //KDEBUG("Created pipe: read_fd=%d, write_fd=%d\n", fd_read, fd_write);
    return 0;
    
cleanup:
    kfree(buffer);
    kfree(read_pipe);
    kfree(write_pipe);
    if (read_file) close_file(read_file);
    if (write_file) close_file(write_file);
    put_inode(inode);
    free_fd(task, fd_read);
    free_fd(task, fd_write);
    return -ENOMEM;
}


static vma_t *find_heap_vma(vm_space_t *vm)
{
    vma_t *vma = vm->vma_list;

    while (vma) {
        if (vma->start == vm->heap_start)
            return vma;
        vma = vma->next;
    }
    return NULL;
}

static void rollback_brk_growth(vm_space_t *vm, uint32_t start, uint32_t end)
{
    for (uint32_t vaddr = start; vaddr < end; vaddr += PAGE_SIZE) {
        uint32_t phys_addr = get_physical_address(vm->pgdir, vaddr);
        if (phys_addr && unmap_user_page(vm->pgdir, vaddr, vm->asid) == 0) {
            free_page((void *)phys_addr);
        }
    }
}

int sys_brk(void* addr)
{
    task_t* task = current_task ;

    uint32_t new_brk = (uint32_t)addr;
    uint32_t old_brk;
    uint32_t addr_to_unmap;
    uint32_t addr_to_map;
    vma_t* heap_vma = NULL;
    
    if (!task ) {
        return -EINVAL;
    }

    process_t* proc = task->process ;
 
    if (!proc || !proc->vm) {
        return -EINVAL;
    }
    
    old_brk = proc->vm->brk;

    /* If addr is NULL, return current brk */
    if (!addr) {
        return (int)old_brk;
    }

    if (new_brk < proc->vm->heap_start || new_brk > proc->vm->heap_end) {
        return -ENOMEM;
    }

    if (new_brk > 0xFFFFFFFFu - (PAGE_SIZE - 1)) {
        return -ENOMEM;
    }

    new_brk = ALIGN_UP(new_brk, PAGE_SIZE);
    if (new_brk > proc->vm->heap_end) {
        return -ENOMEM;
    }

    if (new_brk < old_brk) {
        /* Shrinking heap */
        heap_vma = find_heap_vma(proc->vm);
        if (!heap_vma) return -ENOMEM;
        
        /* Unmap pages */
        for (addr_to_unmap = new_brk; addr_to_unmap < old_brk; addr_to_unmap += PAGE_SIZE) {
            uint32_t phys_addr = get_physical_address(proc->vm->pgdir, addr_to_unmap);
            if (phys_addr) {
                if (unmap_user_page(proc->vm->pgdir, addr_to_unmap, proc->vm->asid) < 0) {
                    return -EFAULT;
                }
                free_page((void *)phys_addr);
            }
        }
        if (new_brk == proc->vm->heap_start) {
            remove_vma(proc->vm, heap_vma->start, heap_vma->end);
        } else {
            heap_vma->end = new_brk;
        }
    } else if (new_brk > old_brk) {
        /* Growing heap */
        heap_vma = find_heap_vma(proc->vm);

        for (addr_to_map = old_brk; addr_to_map < new_brk; addr_to_map += PAGE_SIZE) {
            void *new_page = allocate_page();
            if (!new_page) {
                rollback_brk_growth(proc->vm, old_brk, addr_to_map);
                return -ENOMEM;
            }

            if (map_user_page(proc->vm->pgdir, addr_to_map, (uint32_t)new_page,
                              VMA_READ | VMA_WRITE, proc->vm->asid) < 0) {
                free_page(new_page);
                rollback_brk_growth(proc->vm, old_brk, addr_to_map);
                return -ENOMEM;
            }
        }

        if (!heap_vma) {
            heap_vma = create_vma(proc->vm, proc->vm->heap_start,
                                  new_brk - proc->vm->heap_start,
                                  VMA_READ | VMA_WRITE);
            if (!heap_vma) {
                rollback_brk_growth(proc->vm, old_brk, new_brk);
                return -ENOMEM;
            }
        } else {
            heap_vma->end = new_brk;
        }
    }

    //KDEBUG("sys_brk: New BRK is at 0x%08X\n", new_brk);

    proc->vm->brk = new_brk;
    return (int)new_brk;
}


int sys_dup(int oldfd)
{
    file_t* file;
    int newfd;
    
    if (oldfd < 0 || oldfd >= MAX_FILES) return -EBADF;
    
    file = current_task->process->files[oldfd];
    if (!file) return -EBADF;
    
    newfd = allocate_fd(current_task);
    if (newfd < 0) return -EMFILE;
    
    file->ref_count++;
    current_task->process->files[newfd] = file;
    current_task->process->fd_flags[newfd] = 0;
    
    return newfd;
}

int sys_dup2(int oldfd, int newfd)
{
    file_t* file;
    
    if (oldfd < 0 || oldfd >= MAX_FILES) return -EBADF;
    if (newfd < 0 || newfd >= MAX_FILES) return -EBADF;
    
    if (oldfd == newfd) return newfd;
    
    file = current_task->process->files[oldfd];
    if (!file) return -EBADF;
    
    /* Close newfd if it's open */
    if (current_task->process->files[newfd]) {
        file_t* old_newfd = current_task->process->files[newfd];
        current_task->process->files[newfd] = NULL;
        current_task->process->fd_flags[newfd] = 0;
        close_file(old_newfd);
    }
    
    file->ref_count++;
    current_task->process->files[newfd] = file;
    current_task->process->fd_flags[newfd] = 0;
    
    return newfd;
}

int sys_fcntl(int fd, int cmd, uint32_t arg)
{
    file_t* file;
    int newfd;

    if (!current_task || !current_task->process)
        return -EINVAL;
    if (fd < 0 || fd >= MAX_FILES)
        return -EBADF;

    file = current_task->process->files[fd];
    if (!file)
        return -EBADF;

    switch (cmd) {
    case F_DUPFD:
        if ((int)arg < 0 || arg >= MAX_FILES)
            return -EINVAL;
        for (newfd = (int)arg; newfd < MAX_FILES; newfd++) {
            if (!current_task->process->files[newfd]) {
                file->ref_count++;
                current_task->process->files[newfd] = file;
                current_task->process->fd_flags[newfd] = 0;
                return newfd;
            }
        }
        return -EMFILE;

    case F_GETFD:
        return (current_task->process->fd_flags[fd] & O_CLOEXEC) ? FD_CLOEXEC : 0;

    case F_SETFD:
        if (arg & FD_CLOEXEC)
            current_task->process->fd_flags[fd] |= O_CLOEXEC;
        else
            current_task->process->fd_flags[fd] &= ~O_CLOEXEC;
        return 0;

    case F_GETFL:
        return file->flags;

    case F_SETFL:
        file->flags = (file->flags & O_ACCMODE) |
                      (arg & (O_APPEND | O_NONBLOCK | O_SYNC | O_DSYNC | O_RSYNC));
        return 0;

    default:
        return -EINVAL;
    }
}

int sys_ioctl(int fd, uint32_t request, uint32_t arg)
{
    file_t* file;
    bool is_tty;

    (void)arg;

    if (!current_task || !current_task->process)
        return -EINVAL;
    if (fd < 0 || fd >= MAX_FILES)
        return -EBADF;

    file = current_task->process->files[fd];
    if (!file)
        return -EBADF;

    is_tty = (file->inode == NULL) &&
             (strcmp(file->name, "stdin") == 0 ||
              strcmp(file->name, "stdout") == 0 ||
              strcmp(file->name, "stderr") == 0 ||
              strcmp(file->name, "tty0") == 0);

    switch (request) {
    case TCGETS:
    case TCSETS:
    case TCSETSW:
    case TCSETSF:
        return is_tty ? 0 : -ENOTTY;
    default:
        return -ENOTTY;
    }
}

int sys_time(time_t* tloc)
{
    time_t now = get_current_time();

    if (tloc && copy_to_user(tloc, &now, sizeof(now)) < 0)
        return -EFAULT;

    return (int)now;
}

int sys_gettimeofday(struct timeval* tv, struct timezone* tz)
{
    struct timeval ktv;
    struct timezone ktz;
    uint32_t ticks;

    ticks = get_system_ticks();
    ktv.tv_sec = get_current_time();
    ktv.tv_usec = (ticks % TIMER_FREQ) * (1000000u / TIMER_FREQ);

    if (tv && copy_to_user(tv, &ktv, sizeof(ktv)) < 0)
        return -EFAULT;

    if (tz) {
        ktz.tz_minuteswest = 0;
        ktz.tz_dsttime = 0;
        if (copy_to_user(tz, &ktz, sizeof(ktz)) < 0)
            return -EFAULT;
    }

    return 0;
}

int sys_link(const char* oldpath, const char* newpath)
{
    char *old_kpath, *new_kpath;
    char *old_full, *new_full;
    char *new_parent_path, *new_name;
    inode_t *target, *new_parent;
    int result;

    old_kpath = copy_string_from_user(oldpath);
    if (!old_kpath) return -EFAULT;

    new_kpath = copy_string_from_user(newpath);
    if (!new_kpath) { kfree(old_kpath); return -EFAULT; }

    old_full = resolve_path(old_kpath);
    kfree(old_kpath);
    if (!old_full) { kfree(new_kpath); return -ENOENT; }

    new_full = resolve_path(new_kpath);
    kfree(new_kpath);
    if (!new_full) { kfree(old_full); return -ENOENT; }

    target = path_lookup_ex(old_full, false);
    if (!target) {
        kfree(old_full);
        kfree(new_full);
        return -ENOENT;
    }

    if (S_ISDIR(target->mode)) {
        put_inode(target);
        kfree(old_full);
        kfree(new_full);
        return -EPERM;
    }

    result = split_path(new_full, &new_parent_path, &new_name);
    if (result != 0) {
        put_inode(target);
        kfree(old_full);
        kfree(new_full);
        return result;
    }

    new_parent = path_lookup(new_parent_path);
    if (!new_parent) {
        result = -ENOENT;
    } else if (!inode_permission(new_parent, MAY_WRITE)) {
        result = -EACCES;
    } else if (new_parent->i_op != &ext2_inode_ops || target->i_op != &ext2_inode_ops) {
        result = -EXDEV;
    } else {
        result = ext2_link_inode(new_parent, new_name, target);
    }

    if (new_parent) put_inode(new_parent);
    put_inode(target);
    kfree(old_full);
    kfree(new_full);
    kfree(new_parent_path);
    kfree(new_name);
    return result;
}

int sys_symlink(const char* target, const char* linkpath)
{
    char *target_kpath, *link_kpath;
    char *link_full;
    char *parent_path, *name;
    inode_t *parent;
    int result;

    target_kpath = copy_string_from_user(target);
    if (!target_kpath) return -EFAULT;

    link_kpath = copy_string_from_user(linkpath);
    if (!link_kpath) { kfree(target_kpath); return -EFAULT; }

    link_full = resolve_path(link_kpath);
    kfree(link_kpath);
    if (!link_full) {
        kfree(target_kpath);
        return -ENOENT;
    }

    result = split_path(link_full, &parent_path, &name);
    if (result != 0) {
        kfree(target_kpath);
        kfree(link_full);
        return result;
    }

    parent = path_lookup(parent_path);
    if (!parent) {
        result = -ENOENT;
    } else if (!inode_permission(parent, MAY_WRITE)) {
        result = -EACCES;
    } else if (parent->i_op != &ext2_inode_ops) {
        result = -EROFS;
    } else {
        result = ext2_create_symlink(parent, name, target_kpath);
    }

    if (parent) put_inode(parent);
    kfree(target_kpath);
    kfree(link_full);
    kfree(parent_path);
    kfree(name);
    return result;
}

int sys_readlink(const char* pathname, char* buf, size_t bufsiz)
{
    char *kernel_path;
    char *full_path;
    inode_t *inode;
    char link_target[MAX_PATH];
    int result;

    if (!buf || bufsiz == 0) return -EINVAL;

    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;

    full_path = resolve_path(kernel_path);
    kfree(kernel_path);
    if (!full_path) return -ENOENT;

    inode = path_lookup_ex(full_path, false);
    kfree(full_path);
    if (!inode) return -ENOENT;

    if (!S_ISLNK(inode->mode) || !inode->i_op || !inode->i_op->readlink) {
        put_inode(inode);
        return -EINVAL;
    }

    result = inode->i_op->readlink(inode, link_target,
                                   bufsiz < sizeof(link_target) ? bufsiz : sizeof(link_target));
    if (result >= 0 && copy_to_user(buf, link_target, (size_t)result) < 0)
        result = -EFAULT;

    put_inode(inode);
    return result;
}

int sys_chdir(const char* path)
{
    char* kernel_path;
    char* abs_path;
    inode_t* inode;
    task_t *task = current_task;

    if (!task || !task->process) return -EFAULT;

    kernel_path = copy_string_from_user(path);
    if (!kernel_path) return -EFAULT;

    /* Résoudre en chemin absolu puis canonicaliser (. et .. compris) */
    abs_path = resolve_path(kernel_path);
    kfree(kernel_path);
    if (!abs_path) return -ENOMEM;

    path_canonicalize(abs_path);

    inode = path_lookup(abs_path);
    if (!inode) {
        kfree(abs_path);
        return -ENOENT;
    }

    if (!S_ISDIR(inode->mode)) {
        put_inode(inode);
        kfree(abs_path);
        return -ENOTDIR;
    }

    strncpy(task->process->cwd, abs_path, MAX_PATH - 1);
    task->process->cwd[MAX_PATH - 1] = '\0';

    put_inode(inode);
    kfree(abs_path);
    return 0;
}

int sys_getpgrp(void)
{
    if (!current_task || current_task->type != TASK_TYPE_PROCESS || !current_task->process)
        return -EINVAL;

    return current_task->process->pgid;
}

int sys_setpgid(pid_t pid, pid_t pgid)
{
    task_t *caller = current_task;
    task_t *target;

    if (!caller || caller->type != TASK_TYPE_PROCESS || !caller->process)
        return -EINVAL;

    if (pid < 0 || pgid < 0)
        return -EINVAL;

    if (pid == 0)
        target = caller;
    else
        target = find_process_by_pid(pid);

    if (!target || target->type != TASK_TYPE_PROCESS || !target->process)
        return -ESRCH;

    if (target != caller && target->process->parent != caller)
        return -EPERM;

    if (target->state == TASK_ZOMBIE || target->state == TASK_TERMINATED)
        return -ESRCH;

    if (pgid == 0)
        pgid = target->process->pid;

    target->process->pgid = pgid;
    return 0;
}

int sys_getcwd(char* buf, size_t size)
{
    //const char* cwd = "/";
    task_t *task = current_task;

    if(!task || !task->process){
        return -EFAULT;
    }

    //KDEBUG("sys_getcwd: CWD = %s\n", task->process->cwd);

    size_t len = strlen(task->process->cwd);

    if(len == 0)
        return -EFAULT;
    
    if (size < len + 1) return -ERANGE;
    
    if (copy_to_user(buf, task->process->cwd, len + 1) < 0) {
        return -EFAULT;
    }
    
    return (int)(len + 1);
}

int sys_access(const char* pathname, int mode)
{
    char* kernel_path;
    char* full_path;
    inode_t* inode;
    
    if (mode & ~(MAY_READ | MAY_WRITE | MAY_EXEC)) return -EINVAL;
    
    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;
    
    full_path = resolve_path(kernel_path);
    kfree(kernel_path);

    if (!full_path) return -ENOENT;

    inode = path_lookup(full_path);
    kfree(full_path);
    
    if (!inode) return -ENOENT;

    if (mode != 0 && !inode_permission(inode, mode)) {
        put_inode(inode);
        return -EACCES;
    }
    
    put_inode(inode);
    return 0;
}

int sys_umask(int mask)
{
    process_t* proc = current_task ? current_task->process : NULL;
    mode_t old_mask;

    if (!proc) return -EINVAL;
    
    old_mask = proc->umask;
    proc->umask = (mode_t)mask & 0777;
    return (int)old_mask;
}

int sys_chmod(const char* pathname, mode_t mode)
{
    char* kernel_path;
    char* full_path;
    inode_t* inode;
    int ret = 0;

    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;

    full_path = resolve_path(kernel_path);
    kfree(kernel_path);
    if (!full_path) return -ENOENT;

    inode = path_lookup(full_path);
    kfree(full_path);
    if (!inode) return -ENOENT;

    if (current_uid() != 0 && current_uid() != inode->uid) {
        put_inode(inode);
        return -EPERM;
    }

    if (inode->i_op != &ext2_inode_ops) {
        put_inode(inode);
        return -EROFS;
    }

    inode->mode = (inode->mode & S_IFMT) | (mode & 07777);
    inode->ctime = get_current_time();
    ret = ext2_update_inode_metadata(inode);

    put_inode(inode);
    return ret;
}

int sys_chown(const char* pathname, uid_t owner, gid_t group)
{
    char* kernel_path;
    char* full_path;
    inode_t* inode;
    int ret = 0;

    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;

    full_path = resolve_path(kernel_path);
    kfree(kernel_path);
    if (!full_path) return -ENOENT;

    inode = path_lookup(full_path);
    kfree(full_path);
    if (!inode) return -ENOENT;

    if (current_uid() != 0 && current_uid() != inode->uid) {
        put_inode(inode);
        return -EPERM;
    }

    if (inode->i_op != &ext2_inode_ops) {
        put_inode(inode);
        return -EROFS;
    }

    if ((owner != (uid_t)-1 && owner > 0xFFFFu) ||
        (group != (gid_t)-1 && group > 0xFFFFu)) {
        put_inode(inode);
        return -EINVAL;
    }

    if (owner != (uid_t)-1)
        inode->uid = owner;
    if (group != (gid_t)-1)
        inode->gid = group;

    inode->ctime = get_current_time();
    ret = ext2_update_inode_metadata(inode);

    put_inode(inode);
    return ret;
}

int sys_unlink(const char* pathname)
{
    char* kernel_path;
    char* parent_path;
    char* filename;
    inode_t* parent_inode;
    inode_t* target_inode;
    int result;
    
    /* Copier le chemin depuis l'userspace */
    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;
    
    /* Résoudre le chemin (absolu ou relatif) */
    char* full_path = resolve_path(kernel_path);
    kfree(kernel_path);
    
    if (!full_path) return -ENOENT;

    /* Vérifier que le fichier existe */
    target_inode = path_lookup_ex(full_path, false);
    if (!target_inode) {
        kfree(full_path);
        return -ENOENT;
    }
    
    /* Vérifier que ce n'est pas un répertoire */
    if (S_ISDIR(target_inode->mode)) {
        put_inode(target_inode);
        kfree(full_path);
        return -EISDIR;
    }
    
    /* Séparer le chemin parent et le nom du fichier */
    result = split_path(full_path, &parent_path, &filename);
    if (result != 0) {
        put_inode(target_inode);
        kfree(full_path);
        return result;
    }
    
    /* Trouver le répertoire parent */
    parent_inode = path_lookup(parent_path);
    if (!parent_inode) {
        put_inode(target_inode);
        kfree(full_path);
        kfree(parent_path);
        kfree(filename);
        return -ENOENT;
    }
    
    /* Vérifier les permissions d'écriture sur le parent */
    if (!inode_permission(parent_inode, MAY_WRITE)) {
        put_inode(target_inode);
        put_inode(parent_inode);
        kfree(full_path);
        kfree(parent_path);
        kfree(filename);
        return -EACCES;
    }
    
    /* Supprimer le fichier via l'inode operation */
    result = parent_inode->i_op->unlink(parent_inode, filename);
    
    // Decrementer le compteur de liens 
/*     if (result == 0) {
        target_inode->ref_count--;
        if (target_inode->ref_count == 0) {
            // Plus de references, liberer l'inode 
            remove_inode_from_cache(target_inode);
        }
    } */
    
    put_inode(target_inode);
    put_inode(parent_inode);
    kfree(full_path);
    kfree(parent_path);
    kfree(filename);
    
    return result;
}


int sys_rename(const char* oldpath, const char* newpath)
{
    char *old_kpath, *new_kpath;
    char *old_full, *new_full;
    char *old_parent_path, *old_name;
    char *new_parent_path, *new_name;
    inode_t *old_parent, *new_parent;
    int result;

    old_kpath = copy_string_from_user(oldpath);
    if (!old_kpath) return -EFAULT;

    new_kpath = copy_string_from_user(newpath);
    if (!new_kpath) { kfree(old_kpath); return -EFAULT; }

    old_full = resolve_path(old_kpath); kfree(old_kpath);
    if (!old_full) { kfree(new_kpath); return -ENOENT; }

    new_full = resolve_path(new_kpath); kfree(new_kpath);
    if (!new_full) { kfree(old_full); return -ENOENT; }

    result = split_path(old_full, &old_parent_path, &old_name);
    if (result != 0) { kfree(old_full); kfree(new_full); return result; }

    result = split_path(new_full, &new_parent_path, &new_name);
    if (result != 0) {
        kfree(old_full); kfree(new_full);
        kfree(old_parent_path); kfree(old_name);
        return result;
    }

    old_parent = path_lookup(old_parent_path);
    if (!old_parent) { result = -ENOENT; goto out; }

    new_parent = path_lookup(new_parent_path);
    if (!new_parent) { put_inode(old_parent); result = -ENOENT; goto out; }

    if (old_parent->i_op != new_parent->i_op) {
        result = -EXDEV;
    } else if (!old_parent->i_op || !old_parent->i_op->rename) {
        result = -ENOSYS;
    } else if (!inode_permission(old_parent, MAY_WRITE)) {
        result = -EACCES;
    } else if (!inode_permission(new_parent, MAY_WRITE)) {
        result = -EACCES;
    } else {
        result = old_parent->i_op->rename(old_parent, old_name,
                                          new_parent, new_name);
    }

    put_inode(old_parent);
    put_inode(new_parent);

out:
    kfree(old_full); kfree(new_full);
    kfree(old_parent_path); kfree(old_name);
    kfree(new_parent_path); kfree(new_name);
    return result;
}


int sys_rmdir(const char* pathname)
{
    char* kernel_path;
    char* abs_path;
    char* parent_path;
    char* dir_name;
    inode_t* parent_inode;
    inode_t* target_inode;
    int result;

    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;

    abs_path = resolve_path(kernel_path);
    kfree(kernel_path);
    if (!abs_path) return -ENOMEM;

    target_inode = path_lookup_ex(abs_path, false);
    if (!target_inode) {
        kfree(abs_path);
        return -ENOENT;
    }

    if (!S_ISDIR(target_inode->mode)) {
        put_inode(target_inode);
        kfree(abs_path);
        return -ENOTDIR;
    }

    result = split_path(abs_path, &parent_path, &dir_name);
    if (result != 0) {
        put_inode(target_inode);
        kfree(abs_path);
        return result;
    }

    parent_inode = path_lookup(parent_path);
    if (!parent_inode) {
        put_inode(target_inode);
        kfree(abs_path);
        kfree(parent_path);
        kfree(dir_name);
        return -ENOENT;
    }

    if (!parent_inode->i_op || !parent_inode->i_op->rmdir)
        result = -ENOSYS;
    else if (!inode_permission(parent_inode, MAY_WRITE))
        result = -EACCES;
    else
        result = parent_inode->i_op->rmdir(parent_inode, dir_name);

    put_inode(target_inode);
    put_inode(parent_inode);
    kfree(abs_path);
    kfree(parent_path);
    kfree(dir_name);

    return result;
}


int sys_mkdir(const char* pathname, mode_t mode)
{
    char* kernel_path;
    char* abs_path;
    char* parent_path;
    char* dir_name;
    inode_t* parent_inode;
    int result;

    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;

    abs_path = resolve_path(kernel_path);
    kfree(kernel_path);
    if (!abs_path) return -ENOMEM;

    result = split_path(abs_path, &parent_path, &dir_name);
    if (result != 0) {
        kfree(abs_path);
        return result;
    }

    parent_inode = path_lookup(parent_path);
    if (!parent_inode) {
        kfree(abs_path);
        kfree(parent_path);
        kfree(dir_name);
        return -ENOENT;
    }

    if (!S_ISDIR(parent_inode->mode)) {
        put_inode(parent_inode);
        kfree(abs_path);
        kfree(parent_path);
        kfree(dir_name);
        return -ENOTDIR;
    }

    result = parent_inode->i_op->mkdir(parent_inode, dir_name, mode | S_IFDIR);

    put_inode(parent_inode);
    kfree(abs_path);
    kfree(parent_path);
    kfree(dir_name);

    return result;
}


int sys_nanosleep(const timespec_t *req, timespec_t *rem) {
    uint32_t sleep_ticks;
    uint32_t start_time, elapsed_time;
    uint32_t now;
    bool interrupted;
    
    if (!req) return -EFAULT;
    if (req->nsec >= 1000000000u) return -EINVAL;

    //KDEBUG("sys_nanosleep: req->sec=%u, req->nsec=%u\n", req->sec, req->nsec);
    
    /* Convertir la duree demandee en ticks kernel.
     * TIMER_FREQ vaut 1000: un tick == une milliseconde. Garder ce calcul en
     * 32-bit evite de tirer __aeabi_uldivmod dans le kernel freestanding. */
    if (req->sec > 0xFFFFFFFFu / TIMER_FREQ) {
        sleep_ticks = 0xFFFFFFFFu;
    } else {
        uint32_t nsec_ticks = (req->nsec + 999999u) / 1000000u;
        sleep_ticks = req->sec * TIMER_FREQ;
        if (sleep_ticks > 0xFFFFFFFFu - nsec_ticks)
            sleep_ticks = 0xFFFFFFFFu;
        else
            sleep_ticks += nsec_ticks;
    }

    //KDEBUG("sys_nanosleep: sleep_ticks=%u\n", sleep_ticks);
    
    if (sleep_ticks == 0) {
        yield();  /* Juste céder le CPU */
        return 0;
    }
    
    start_time = get_system_ticks();
    //KDEBUG("sys_nanosleep: start_time=%u\n", start_time);
    
    spin_lock(&task_lock);
        /* Mettre le processus en sommeil */
    current_task->state = TASK_INTERRUPTIBLE;
    if (current_task->process)
        current_task->process->state = (proc_state_t)PROC_INTERRUPTIBLE;
    current_task->wakeup_time = start_time + sleep_ticks;
    spin_unlock(&task_lock);
    
    yield();
    
    //KDEBUG("sys_nanosleep: woke up\n");

    /* Vérifier si réveillé par signal */
    now = get_system_ticks();
    interrupted = has_pending_signals(current_task) ||
        (current_task->state == TASK_RUNNING &&
         current_task->wakeup_time > 0 &&
         now < current_task->wakeup_time);

    spin_lock(&task_lock);
    current_task->wakeup_time = 0;
    spin_unlock(&task_lock);

    if (interrupted) {
        /* Réveillé prématurément par un signal */
        if (rem) {
            elapsed_time = now - start_time;
            uint32_t remaining_ticks = (elapsed_time >= sleep_ticks) ? 0 : sleep_ticks - elapsed_time;
            rem->sec = remaining_ticks / TIMER_FREQ;
            rem->nsec = (remaining_ticks % TIMER_FREQ) * (1000000000u / TIMER_FREQ);
        }
        return -EINTR;
    }

    return 0;
}

static process_t *task_process_for_sysinfo(task_t *task)
{
    if (!task) return NULL;
    if (task->type == TASK_TYPE_PROCESS)
        return task->process;
    if (task->type == TASK_TYPE_THREAD && task->thread.process &&
        task->thread.process->type == TASK_TYPE_PROCESS)
        return task->thread.process->process;
    return NULL;
}

static uint32_t vm_virtual_kb(vm_space_t *vm)
{
    uint32_t bytes = 0;
    for (vma_t *vma = vm ? vm->vma_list : NULL; vma; vma = vma->next) {
        if (vma->end > vma->start)
            bytes += vma->end - vma->start;
    }
    return bytes / 1024;
}

static uint32_t vm_rss_kb(vm_space_t *vm)
{
    uint32_t pages = 0;
    if (!vm || !vm->pgdir) return 0;

    for (uint32_t i = 0; i < 1024; i++) {
        uint32_t l1_entry = vm->pgdir[i];
        if ((l1_entry & 0x3) != 0x1)
            continue;

        uint32_t *l2_table = (uint32_t *)(l1_entry & 0xFFFFFC00);
        for (uint32_t j = 0; j < 256; j++) {
            if ((l2_table[j] & 0x3) != 0)
                pages++;
        }
    }

    return (pages * PAGE_SIZE) / 1024;
}

static uint32_t vm_l2_table_count(vm_space_t *vm)
{
    uint32_t count = 0;
    if (!vm || !vm->pgdir) return 0;

    for (uint32_t i = 0; i < 1024; i++) {
        if ((vm->pgdir[i] & 0x3) == 0x1)
            count++;
    }
    return count;
}

int sys_sysinfo(struct sysinfo_response *resp)
{
    if (!resp) return -EINVAL;

    static const char state_char[8] = {
        'S', /* TASK_READY           */
        'R', /* TASK_RUNNING         */
        'S', /* TASK_BLOCKED         */
        'Z', /* TASK_ZOMBIE          */
        'T', /* TASK_TERMINATED      */
        'S', /* TASK_INTERRUPTIBLE   */
        'D', /* TASK_UNINTERRUPTIBLE */
        't', /* TASK_STOPPED         */
    };

    struct sysinfo_response *local = kmalloc(sizeof(struct sysinfo_response));
    if (!local) return -ENOMEM;
    memset(local, 0, sizeof(struct sysinfo_response));

    /* Mémoire système */
    local->mem_total_kb = (get_total_page_count() * PAGE_SIZE) / 1024;
    local->mem_free_kb  = (get_free_page_count()  * PAGE_SIZE) / 1024;
    local->tasks_created = kernel_lifecycle_stats.tasks_created;
    local->tasks_destroyed = kernel_lifecycle_stats.tasks_destroyed;
    local->zombies_created = kernel_lifecycle_stats.zombies_created;
    local->zombies_reaped = kernel_lifecycle_stats.zombies_reaped;
    local->failed_forks = kernel_lifecycle_stats.failed_forks;
    local->scheduler_refused = kernel_lifecycle_stats.scheduler_refused;
    local->ready_queue_refused = kernel_lifecycle_stats.ready_queue_refused;
    local->stack_pages_allocated = kernel_lifecycle_stats.stack_pages_allocated;
    local->stack_pages_freed = kernel_lifecycle_stats.stack_pages_freed;
    local->asid_rollovers = kernel_lifecycle_stats.asid_rollovers;
    local->state_sync_repairs = kernel_lifecycle_stats.state_sync_repairs;
    local->blocked_signal_wakeups = kernel_lifecycle_stats.blocked_signal_wakeups;
    local->tty_stale_waiters = kernel_lifecycle_stats.tty_stale_waiters;
    local->uninterruptible_timeouts = kernel_lifecycle_stats.uninterruptible_timeouts;

    /* Uptime pour %CPU */
    uint32_t uptime = get_system_ticks();
    if (uptime == 0) uptime = 1;

    /* Liste des tâches */
    int count = 0;
    task_t *task = task_list_head;
    if (!task) goto out;

    do {
        if (count >= 64) break;
        struct proc_info *p = &local->procs[count];
        process_t *proc = task_process_for_sysinfo(task);

        p->tid      = task->task_id;
        p->pid      = proc ? proc->pid : 0;
        p->ppid     = proc ? proc->ppid : 0;
        p->sid      = proc ? proc->sid : 0;
        p->tty      = proc ? proc->controlling_tty : -1;
        p->uid      = proc ? proc->uid : 0;
        p->gid      = proc ? proc->gid : 0;
        p->priority = task->priority;
        p->switches = task->switch_count;
        p->page_faults = task->page_faults;
        p->cow_faults = task->cow_faults;
        p->stack_faults = task->stack_faults;
        /* Division 64-bit évitée : on scale down en uint32 avant de diviser */
        uint32_t rt32 = (task->total_runtime >= (uint64_t)uptime)
                        ? uptime : (uint32_t)task->total_runtime;
        uint32_t u = uptime, r = rt32;
        while (u > 0x00100000u) { u >>= 1; r >>= 1; }
        p->cpu_pct_x10 = u ? (r * 1000u) / u : 0u;
        p->stack_kb = task->stack_size / 1024;
        p->state    = (task->state < 8) ? state_char[task->state] : '?';

        switch (task->type) {
            case TASK_TYPE_PROCESS: p->type = 'P'; break;
            case TASK_TYPE_THREAD:  p->type = 'T'; break;
            default:                p->type = 'K'; break;
        }

        if (proc && proc->vm) {
            vm_space_t *vm = proc->vm;
            uint32_t used = (vm->brk > vm->heap_start) ? (vm->brk - vm->heap_start) : 0;
            p->heap_kb = used / 1024;
            p->vm_kb = vm_virtual_kb(vm);
            p->rss_kb = vm_rss_kb(vm);
            p->l2_tables = vm_l2_table_count(vm);
        }

        int i;
        for (i = 0; i < 31 && task->name[i]; i++)
            p->name[i] = task->name[i];
        p->name[i] = '\0';

        count++;
        task = task->next;
    } while (task && task != task_list_head);

out:
    local->proc_count = count;

    int ret = count;
    if (copy_to_user(resp, local, sizeof(struct sysinfo_response)) < 0)
        ret = -EFAULT;

    kfree(local);
    return ret;
}
