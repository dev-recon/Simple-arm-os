#include <kernel/mount.h>
#include <kernel/vfs.h>
#include <kernel/fat32.h>
#include <kernel/file.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>
#include <kernel/memory.h>
#include <kernel/string.h>
#include <kernel/procfs.h>

#define FSTAB_MAX_SIZE   2048
#define FSTAB_FIELD_MAX  64

/* File operations for FAT32 */
extern file_operations_t fat32_dir_ops;
extern inode_operations_t fat32_inode_ops;

static inode_t* vfs_create_fat32_root_inode(void)
{
    inode_t* fat32_root = create_inode();
    if (!fat32_root) {
        return NULL;
    }

    fat32_root->ino = 1;
    fat32_root->mode = S_IFDIR | 0777;
    fat32_root->uid = 0;
    fat32_root->gid = 0;
    fat32_root->size = 0;
    fat32_root->first_cluster = get_fat32_root_cluster();
    fat32_root->i_op = &fat32_inode_ops;
    fat32_root->f_op = &fat32_dir_ops;
    fat32_root->atime = 0;
    fat32_root->mtime = 0;
    fat32_root->ctime = 0;

    return fat32_root;
}

static int vfs_read_small_file(const char* path, char* buffer, size_t size)
{
    if (!path || !buffer || size == 0) {
        return -EINVAL;
    }

    inode_t* inode = path_lookup(path);
    if (!inode) {
        return -ENOENT;
    }

    if (!S_ISREG(inode->mode) || !inode->f_op || !inode->f_op->read) {
        put_inode(inode);
        return -EINVAL;
    }

    file_t file;
    memset(&file, 0, sizeof(file));
    file.inode = inode;
    file.flags = O_RDONLY;
    file.ref_count = 1;
    file.f_op = inode->f_op;
    file.offset = 0;

    int open_ret = 0;
    if (file.f_op->open) {
        open_ret = file.f_op->open(inode, &file);
        if (open_ret < 0) {
            put_inode(inode);
            return open_ret;
        }
    }

    ssize_t read_ret = file.f_op->read(&file, buffer, size - 1);

    if (file.f_op->close) {
        file.f_op->close(&file);
    }
    put_inode(inode);

    if (read_ret < 0) {
        return (int)read_ret;
    }

    buffer[read_ret] = '\0';
    return (int)read_ret;
}

static bool fstab_next_field(char** cursor, char* out, size_t out_size)
{
    char* p;
    size_t len = 0;

    if (!cursor || !*cursor || !out || out_size == 0) {
        return false;
    }

    p = *cursor;
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }

    if (*p == '\0' || *p == '#') {
        *cursor = p;
        return false;
    }

    while (*p && !isspace((unsigned char)*p) && *p != '#') {
        if (len + 1 < out_size) {
            out[len++] = *p;
        }
        p++;
    }

    out[len] = '\0';
    *cursor = p;
    return len > 0;
}

static const disk_partition_t* vfs_find_partition_by_device(const char* device)
{
    if (!device) {
        return NULL;
    }

    if (strncmp(device, "/dev/", 5) == 0) {
        device += 5;
    }

    for (int i = 0; i < DISK_PART_COUNT; i++) {
        if (strcmp(device, kernel_disk_partitions[i].name) == 0) {
            return &kernel_disk_partitions[i];
        }
    }

    return NULL;
}

int vfs_mount_fat32_partition(const disk_partition_t* part)
{
    if (!part || part->fs_type != DISK_FS_FAT32) {
        return -EINVAL;
    }

    if (init_fat32() != 0) {
        KERROR("[VFS] Failed to initialize FAT32\n");
        return -EIO;
    }

    KINFO("[VFS] Mounting %s (%s) at LBA %u\n",
          part->name, part->mountpoint, (uint32_t)part->lba_start);

    if (mount_fat32_filesystem_at(part->lba_start) != 0) {
        KERROR("[VFS] Failed to mount FAT32 from %s\n", part->name);
        return -EIO;
    }

    inode_t* fat32_root = vfs_create_fat32_root_inode();
    if (!fat32_root) {
        KERROR("[VFS] Failed to create FAT32 root inode\n");
        return -ENOMEM;
    }

    if (vfs_mount_ex(part->mountpoint, fat32_root, part->name, "fat32", "rw") != 0) {
        KERROR("[VFS] vfs_mount %s failed\n", part->mountpoint);
        put_inode(fat32_root);
        return -EIO;
    }

    return 0;
}

static int vfs_mount_fstab_entry(const char* device, const char* mountpoint,
                                 const char* fs_type)
{
    const disk_partition_t* part = vfs_find_partition_by_device(device);
    if (!part) {
        KERROR("[VFS] fstab: unknown device %s\n", device);
        return -ENODEV;
    }

    if (strcmp(mountpoint, "/") == 0) {
        if (part->fs_type != DISK_FS_EXT2 || strcmp(fs_type, "ext2") != 0) {
            KERROR("[VFS] fstab: root entry does not match mounted ext2 root\n");
            return -EINVAL;
        }
        return 0;
    }

    if (strcmp(fs_type, "fat32") == 0) {
        if (part->fs_type != DISK_FS_FAT32 || strcmp(mountpoint, part->mountpoint) != 0) {
            KERROR("[VFS] fstab: FAT32 entry mismatch for %s on %s\n",
                   device, mountpoint);
            return -EINVAL;
        }
        return vfs_mount_fat32_partition(part);
    }

    KERROR("[VFS] fstab: unsupported filesystem type %s\n", fs_type);
    return -ENODEV;
}

int vfs_mount_from_fstab(const char* path)
{
    char buffer[FSTAB_MAX_SIZE];
    KINFO("[VFS] Loading mounts from %s\n", path);

    int bytes = vfs_read_small_file(path, buffer, sizeof(buffer));
    if (bytes < 0) {
        KERROR("[VFS] Could not read %s (%d), using static fallback\n", path, bytes);
        return bytes;
    }

    int mounted = 0;
    char* line = buffer;
    while (*line) {
        char* next = strchr(line, '\n');
        if (next) {
            *next = '\0';
        }

        char* cursor = line;
        char device[FSTAB_FIELD_MAX];
        char mountpoint[FSTAB_FIELD_MAX];
        char fs_type[FSTAB_FIELD_MAX];
        char options[FSTAB_FIELD_MAX];

        if (fstab_next_field(&cursor, device, sizeof(device)) &&
            fstab_next_field(&cursor, mountpoint, sizeof(mountpoint)) &&
            fstab_next_field(&cursor, fs_type, sizeof(fs_type)) &&
            fstab_next_field(&cursor, options, sizeof(options))) {
            (void)options;

            int ret = vfs_mount_fstab_entry(device, mountpoint, fs_type);
            if (ret == 0 && strcmp(mountpoint, "/") != 0) {
                mounted++;
            }
        }

        if (!next) {
            break;
        }
        line = next + 1;
    }

    return mounted;
}

int vfs_mount_user(const char* source, const char* target, const char* fstype,
                   uint32_t flags, const void* data)
{
    const disk_partition_t* part;
    inode_t* target_inode;
    inode_t* proc_root;

    (void)flags;
    (void)data;

    if (!source || !target || !fstype)
        return -EINVAL;
    if (strcmp(target, "/") == 0)
        return -EBUSY;
    if (vfs_is_mounted(target))
        return -EBUSY;

    if (strcmp(fstype, "proc") == 0) {
        if (strcmp(source, "proc") != 0 && strcmp(source, "none") != 0)
            return -EINVAL;

        target_inode = path_lookup(target);
        if (target_inode) {
            if (!S_ISDIR(target_inode->mode)) {
                put_inode(target_inode);
                return -ENOTDIR;
            }
            put_inode(target_inode);
        }

        proc_root = procfs_mount();
        if (!proc_root)
            return -ENOMEM;

        if (vfs_mount_ex(target, proc_root, "proc", "proc",
                         "rw,nosuid,nodev,noexec") != 0) {
            put_inode(proc_root);
            return -EIO;
        }
        return 0;
    }

    target_inode = path_lookup(target);
    if (!target_inode)
        return -ENOENT;
    if (!S_ISDIR(target_inode->mode)) {
        put_inode(target_inode);
        return -ENOTDIR;
    }
    put_inode(target_inode);

    if (strcmp(fstype, "fat32") == 0) {
        part = vfs_find_partition_by_device(source);
        if (!part || part->fs_type != DISK_FS_FAT32)
            return -ENODEV;
        if (strcmp(target, part->mountpoint) != 0)
            return -EINVAL;
        return vfs_mount_fat32_partition(part);
    }

    if (strcmp(fstype, "ext2") == 0)
        return -EBUSY;

    return -ENODEV;
}
