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

/* Forward declarations de toutes les fonctions statiques */
extern bool fat32_directory_is_not_empty(uint32_t dir_cluster);      // FIX THE DEPENDENCY TO FAT32
extern int fat32_remove_dir_entry(uint32_t dir_cluster, const char* name);
extern void fat32_free_cluster(uint32_t cluster);
extern char* resolve_path(const char* path);

bool can_read(file_t* file) {
    /* Méthode 1: Exclusion - si pas write-only, alors readable */
    return (file->flags & O_ACCMODE) != O_WRONLY;
}

bool can_write(file_t* file) {
    /* Si contient O_WRONLY ou O_RDWR */
    return (file->flags & O_ACCMODE) != O_RDONLY;
}

/* Lecture depuis un pipe */
ssize_t pipe_read(file_t* file, void* buf, size_t count) {
    struct pipe_inode_info *pipe = file->private_data;
    struct pipe_buffer *buffer = pipe->buffer;
    char *user_buf = (char*)buf;
    size_t bytes_read = 0;

    //KDEBUG("ENTERING READING FROM PIPE\n");
    //KDEBUG("file->flags = 0x%08X\n", file->flags);

    /* Vérifier que c'est ouvert en lecture */
    if (can_write(file)) {
        return -EBADF;
    }

    /* Si pas de données et plus d'écrivains -> EOF */
    if (buffer->count == 0 && (buffer->writers == 0 || buffer->closed_write)) {
        return 0;  /* EOF */
    }
    
    /* Si pas de données, retourner EAGAIN */
    if (buffer->count == 0) {
        return -EAGAIN;
    }


    
    /* Lire les données disponibles */
    while (bytes_read < count && buffer->count > 0) {
        user_buf[bytes_read] = buffer->data[buffer->read_pos];
        buffer->read_pos = (buffer->read_pos + 1) % PIPE_BUF_SIZE;
        buffer->count--;
        bytes_read++;
    }
    
    return bytes_read;
}

/* Écriture vers un pipe */
ssize_t pipe_write(file_t* file, const void* buf, size_t count) {
    struct pipe_inode_info *pipe = file->private_data;
    struct pipe_buffer *buffer = pipe->buffer;
    const char *user_buf = (const char*)buf;
    size_t bytes_written = 0;
    

    /* Vérifier que c'est ouvert en écriture */
    if (can_read(file)) {
        return -EBADF;
    }
    
    /* Si pas de lecteurs -> SIGPIPE */
    if (buffer->readers == 0 || buffer->closed_read) {
        return -EPIPE;
    }
    
    /* Si buffer plein, retourner EAGAIN */
    if (buffer->count == PIPE_BUF_SIZE) {
        return -EAGAIN;
    }

    //KDEBUG("WRITING TO PIPE\n");
    
    /* Écrire tant qu'il y a de la place */
    while (bytes_written < count && buffer->count < PIPE_BUF_SIZE) {
        buffer->data[buffer->write_pos] = user_buf[bytes_written];
        buffer->write_pos = (buffer->write_pos + 1) % PIPE_BUF_SIZE;
        buffer->count++;
        bytes_written++;
    }
    
    //KDEBUG("DATA WROTE TO PIPE\n");
    return bytes_written;
}

int pipe_close(file_t* file) {
    struct pipe_inode_info *pipe = file->private_data;
    struct pipe_buffer *buffer = pipe->buffer;
    
    //KDEBUG("CLOSING PIPE\n");

    /* Déterminer si c'était un lecteur ou écrivain */
    if (file->flags & (O_RDONLY | O_RDWR)) {
        buffer->readers--;
        if (buffer->readers == 0) {
            buffer->closed_read = 1;
        }
    }
    
    if (file->flags & (O_WRONLY | O_RDWR)) {
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
    write_file->offset = 0;
    write_file->flags = O_WRONLY;       /* ← Utilise le champ flags */
    write_file->ref_count = 1;
    write_file->f_op = &pipe_write_fops;
    write_file->private_data = write_pipe;
    
    /* Associer aux descripteurs */
    task->process->files[fd_read] = read_file;
    task->process->files[fd_write] = write_file;
    
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


int sys_brk(void* addr)
{
    task_t* task = current_task ;

    uint32_t new_brk = (uint32_t)addr;
    uint32_t old_brk;
    uint32_t addr_to_unmap;
    uint32_t addr_to_map;
    vma_t* heap_vma = NULL;
    vma_t* new_vma = NULL;
    
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
    
    /* Align to page boundary */
    new_brk = ALIGN_UP(new_brk, PAGE_SIZE);

    //KDEBUG("sys_brk: new_brk = 0x%08X, old_brk = 0x%08X\n", new_brk, old_brk);
    
    if (new_brk < old_brk) {
        /* Shrinking heap */
        heap_vma = find_vma(proc->vm, proc->vm->heap_start);
        if (!heap_vma) return -ENOMEM;
        
        /* Unmap pages */
        for (addr_to_unmap = new_brk; addr_to_unmap < old_brk; addr_to_unmap += PAGE_SIZE) {
            if (addr_to_unmap >= proc->vm->heap_start) {
                uint32_t phys_addr = get_physical_address(proc->vm->pgdir ,addr_to_unmap);
                free_page((void *)phys_addr);
                unmap_user_page(proc->vm->pgdir, addr_to_unmap);
            }
        }

    } else if (new_brk >= old_brk) {
        /* Growing heap */
        heap_vma = find_vma(proc->vm, proc->vm->heap_start);
        if(!heap_vma)
        {
            new_vma = create_vma(proc->vm, proc->vm->heap_start, PAGE_SIZE, VMA_READ | VMA_WRITE);
        }

        if (!new_vma) return -ENOMEM;
        
        /* Check if we have enough space */
        if (new_brk > proc->vm->stack_start) {
            return -ENOMEM;
        }

        if(new_brk == old_brk)
            new_brk += PAGE_SIZE ;

        for (addr_to_map = old_brk; addr_to_map < new_brk; addr_to_map += PAGE_SIZE) {
            if (addr_to_map >= proc->vm->heap_start) {

                void * new_page = allocate_page();

                //KDEBUG("sys_brk: allocating new page at vaddr = 0x%08X, paddr = 0x%08X\n", addr_to_map, (uint32_t)new_page);


                if (!new_page) {
                    return -ENOMEM;
                }
        
                // Zero the page
                memset((void *)new_page, 0, PAGE_SIZE);
                
                // Map new page in process PGDIR
                map_user_page(proc->vm->pgdir, addr_to_map, (uint32_t)new_page, 
                            VMA_READ | VMA_WRITE, proc->vm->asid);

            }
        }
        
        // FIX IT  Pages will be allocated on demand via page faults
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
        close_file(current_task->process->files[newfd]);
    }
    
    file->ref_count++;
    current_task->process->files[newfd] = file;
    
    return newfd;
}

int sys_chdir(const char* path)
{
    char* kernel_path;
    inode_t* inode;
    task_t *task = current_task;
    
    if(!task || !task->process) return -EFAULT;

    kernel_path = copy_string_from_user(path);
    if (!kernel_path) return -EFAULT;
    
    inode = path_lookup(kernel_path);
    
    if (!inode){
        kfree(kernel_path);
        return -ENOENT;
    } 
    
    if (!S_ISDIR(inode->mode)) {
        put_inode(inode);
        kfree(kernel_path);
        return -ENOTDIR;
    }
    //KDEBUG("ABOUT TO CHANGE CURRENT DIR\n");
    //KDEBUG("CWD = %s\n", task->process->cwd);
    //KDEBUG("kernel_path = %s\n", kernel_path);

    strcpy(task->process->cwd, kernel_path);
    /* TODO: Update current working directory */
    put_inode(inode);
    //KDEBUG("2 CWD = %s\n", task->process->cwd);

    return 0;
}

int sys_getcwd(char* buf, size_t size)
{
    //const char* cwd = "/";
    task_t *task = current_task;

    if(!task || !task->process){
        return -EFAULT;
    }

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
    inode_t* inode;
    
    /* Suppression du warning unused parameter */
    (void)mode;
    
    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;
    
    inode = path_lookup(kernel_path);
    kfree(kernel_path);
    
    if (!inode) return -ENOENT;
    
    put_inode(inode);
    return 0;
}

int sys_umask(int mask)
{
    /* Suppression du warning unused parameter */
    (void)mask;
    
    /* TODO: Implement umask */
    return 022; /* Default umask */
}

int sys_chmod(const char* pathname, mode_t mode)
{
    /* Suppression des warnings unused parameter */
    (void)pathname;
    (void)mode;
    
    /* TODO: Implement chmod */
    return -ENOSYS;
}

int sys_chown(const char* pathname, uid_t owner, gid_t group)
{
    /* Suppression des warnings unused parameter */
    (void)pathname;
    (void)owner;
    (void)group;
    
    /* TODO: Implement chown */
    return -ENOSYS;
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
    target_inode = path_lookup(full_path);
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


int sys_rmdir(const char* pathname)
{
    char* kernel_path;
    char* parent_path;
    char* dir_name;
    inode_t* parent_inode;
    inode_t* target_inode;
    int result;
    
    /* Copier le chemin depuis l'userspace */
    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;
    
    /* Vérifier le répertoire à supprimer */
    target_inode = path_lookup(kernel_path);
    if (!target_inode) {
        kfree(kernel_path);
        return -ENOENT;
    }
    
    /* Vérifier que c'est un répertoire */
    if (!S_ISDIR(target_inode->mode)) {
        put_inode(target_inode);
        kfree(kernel_path);
        return -ENOTDIR;
    }
    
    /* Vérifier que le répertoire est vide */
    if (fat32_directory_is_not_empty(target_inode->first_cluster)) {
        put_inode(target_inode);
        kfree(kernel_path);
        return -ENOTEMPTY;
    }
    
    /* Séparer parent et nom */
    result = split_path(kernel_path, &parent_path, &dir_name);
    if (result != 0) {
        put_inode(target_inode);
        kfree(kernel_path);
        return result;
    }
    
    /* Trouver le répertoire parent */
    parent_inode = path_lookup(parent_path);
    if (!parent_inode) {
        put_inode(target_inode);
        kfree(kernel_path);
        kfree(parent_path);
        kfree(dir_name);
        return -ENOENT;
    }
    
    /* Supprimer l'entrée du répertoire parent */
    result = fat32_remove_dir_entry(parent_inode->first_cluster, dir_name);
    if (result == 0) {
        /* Libérer le cluster du répertoire */
        fat32_free_cluster(target_inode->first_cluster);
    }
    
    put_inode(target_inode);
    put_inode(parent_inode);
    kfree(kernel_path);
    kfree(parent_path);
    kfree(dir_name);
    
    return result;
}


int sys_mkdir(const char* pathname, mode_t mode)
{
    char* kernel_path;
    char* parent_path;
    char* dir_name;
    inode_t* parent_inode;
    int result;
    
    /* Copier le chemin depuis l'userspace */
    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;
    
    /* Séparer parent et nom du répertoire */
    result = split_path(kernel_path, &parent_path, &dir_name);
    if (result != 0) {
        kfree(kernel_path);
        return result;
    }
    
    /* Trouver le répertoire parent */
    parent_inode = path_lookup(parent_path);
    if (!parent_inode) {
        kfree(kernel_path);
        kfree(parent_path);
        kfree(dir_name);
        return -ENOENT;
    }
    
    /* Vérifier que le parent est un répertoire */
    if (!S_ISDIR(parent_inode->mode)) {
        put_inode(parent_inode);
        kfree(kernel_path);
        kfree(parent_path);
        kfree(dir_name);
        return -ENOTDIR;
    }
    
    /* Créer le répertoire via l'inode operation */
    result = parent_inode->i_op->mkdir(parent_inode, dir_name, mode | S_IFDIR);
    
    put_inode(parent_inode);
    kfree(kernel_path);
    kfree(parent_path);
    kfree(dir_name);
    
    return result;
}



