#include <kernel/syscalls.h>
#include <kernel/process.h>
#include <kernel/memory.h>
#include <kernel/vfs.h>
#include <kernel/kernel.h>
#include <kernel/string.h>
#include <kernel/task.h>
#include <kernel/userspace.h>
#include <kernel/kprintf.h>

/* Forward declarations de toutes les fonctions statiques */

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

    KDEBUG("sys_brk: new_brk = 0x%08X, old_brk = 0x%08X\n", new_brk, old_brk);
    
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

                KDEBUG("sys_brk: allocating new page at vaddr = 0x%08X, paddr = 0x%08X\n", addr_to_map, (uint32_t)new_page);


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

    KDEBUG("sys_brk: New BRK is at 0x%08X\n", new_brk);

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

int sys_pipe(int pipefd[2])
{
    /* TODO: Implement pipes */
    (void)pipefd;
    return -ENOSYS;
}

int sys_chdir(const char* path)
{
    char* kernel_path;
    inode_t* inode;
    
    kernel_path = copy_string_from_user(path);
    if (!kernel_path) return -EFAULT;
    
    inode = path_lookup(kernel_path);
    kfree(kernel_path);
    
    if (!inode) return -ENOENT;
    
    if (!S_ISDIR(inode->mode)) {
        put_inode(inode);
        return -ENOTDIR;
    }
    
    /* TODO: Update current working directory */
    put_inode(inode);
    
    return 0;
}

int sys_getcwd(char* buf, size_t size)
{
    const char* cwd = "/";
    size_t len = strlen(cwd);
    
    if (size < len + 1) return -ERANGE;
    
    if (copy_to_user(buf, cwd, len + 1) < 0) {
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
    
    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;
    
    kfree(kernel_path);
    
    /* TODO: Implement unlink */
    return -ENOSYS;
}

int sys_rmdir(const char* pathname)
{
    char* kernel_path;
    
    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;
    
    kfree(kernel_path);
    
    /* TODO: Implement rmdir */
    return -ENOSYS;
}

int sys_mkdir(const char* pathname, mode_t mode)
{
    char* kernel_path;
    
    /* Suppression du warning unused parameter */
    (void)mode;
    
    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;
    
    kfree(kernel_path);
    
    /* TODO: Implement mkdir */
    return -ENOSYS;
}

