/* kernel/fs/ext2_vfs.c - Ext2 VFS driver */
#include <kernel/ext2.h>
#include <kernel/vfs.h>
#include <kernel/memory.h>
#include <kernel/string.h>
#include <kernel/kprintf.h>
#include <kernel/kernel.h>
#include <kernel/file.h>

extern int blk_read_sectors(uint64_t lba, uint32_t count, void* buffer);
extern int blk_write_sectors(uint64_t lba, uint32_t count, void* buffer);
extern inode_t* create_inode(void);
extern void put_inode(inode_t* inode);

static ext2_fs_t ext2_fs;

/* Forward declarations */
static inode_t* ext2_inode_lookup(inode_t* dir, const char* name);
static ssize_t  ext2_file_read(file_t* file, void* buffer, size_t count);
static ssize_t  ext2_file_write(file_t* file, const void* buffer, size_t count);
static int      ext2_file_open(inode_t* inode, file_t* file);
static int      ext2_file_close(file_t* file);
static off_t    ext2_file_lseek(file_t* file, off_t offset, int whence);
static int      ext2_dir_readdir(file_t* file, dirent_t* dirent);

file_operations_t ext2_file_ops = {
    .read    = ext2_file_read,
    .write   = ext2_file_write,
    .open    = ext2_file_open,
    .close   = ext2_file_close,
    .lseek   = ext2_file_lseek,
    .readdir = NULL,
};

file_operations_t ext2_dir_ops = {
    .read    = NULL,
    .write   = NULL,
    .open    = ext2_file_open,
    .close   = ext2_file_close,
    .lseek   = NULL,
    .readdir = ext2_dir_readdir,
};

inode_operations_t ext2_inode_ops = {
    .lookup = ext2_inode_lookup,
    .create = NULL,
    .mkdir  = NULL,
    .unlink = NULL,
    .rename = NULL,
};

static bool ext2_valid_disk_inode_ptr(const ext2_inode_t* di)
{
    uint32_t start = (uint32_t)di;
    uint32_t end = start + sizeof(*di) - 1;

    return di && end >= start && IS_VALID_RAM(start) && IS_VALID_RAM(end);
}

/* ---------- block I/O ---------- */

static int ext2_read_block(uint32_t block, void* buf)
{
    uint64_t lba = ext2_fs.lba_start + (uint64_t)block * ext2_fs.sectors_per_block;
    return blk_read_sectors(lba, ext2_fs.sectors_per_block, buf);
}

static int ext2_write_block(uint32_t block, void* buf)
{
    uint64_t lba = ext2_fs.lba_start + (uint64_t)block * ext2_fs.sectors_per_block;
    return blk_write_sectors(lba, ext2_fs.sectors_per_block, buf);
}

/* ---------- inode table ---------- */

static int ext2_read_disk_inode(uint32_t ino, ext2_inode_t* out)
{
    if (ino == 0) return -1;

    uint32_t group  = (ino - 1) / ext2_fs.inodes_per_group;
    uint32_t local  = (ino - 1) % ext2_fs.inodes_per_group;

    /* Which block inside the group descriptor table holds this group's entry? */
    uint32_t descs_per_block = ext2_fs.block_size / sizeof(ext2_group_desc_t);
    uint32_t gdesc_blk       = ext2_fs.gdesc_block + group / descs_per_block;
    uint32_t gdesc_idx       = group % descs_per_block;

    uint8_t* blkbuf = kmalloc(ext2_fs.block_size);
    if (!blkbuf) return -1;

    if (ext2_read_block(gdesc_blk, blkbuf) < 0) {
        kfree(blkbuf);
        return -1;
    }

    ext2_group_desc_t* gd  = (ext2_group_desc_t*)blkbuf + gdesc_idx;
    uint32_t itable_block  = gd->bg_inode_table;
    kfree(blkbuf);

    uint32_t inodes_per_block = ext2_fs.block_size / ext2_fs.inode_size;
    uint32_t inode_block      = itable_block + local / inodes_per_block;
    uint32_t inode_off        = (local % inodes_per_block) * ext2_fs.inode_size;

    blkbuf = kmalloc(ext2_fs.block_size);
    if (!blkbuf) return -1;

    if (ext2_read_block(inode_block, blkbuf) < 0) {
        kfree(blkbuf);
        return -1;
    }

    memcpy(out, blkbuf + inode_off, sizeof(ext2_inode_t));
    kfree(blkbuf);
    return 0;
}

/* Resolve logical block index → physical block number.
   Handles direct (0-11) and single-indirect (12). */
static uint32_t ext2_get_block_at(ext2_inode_t* di, uint32_t idx)
{
    if (idx < 12)
        return di->i_block[idx];

    idx -= 12;
    uint32_t ptrs_per_block = ext2_fs.block_size / 4;
    if (idx >= ptrs_per_block) return 0;   /* double-indirect: not needed RO */

    if (di->i_block[12] == 0) return 0;

    uint32_t* indirect = kmalloc(ext2_fs.block_size);
    if (!indirect) return 0;
    if (ext2_read_block(di->i_block[12], indirect) < 0) {
        kfree(indirect);
        return 0;
    }
    uint32_t blk = indirect[idx];
    kfree(indirect);
    return blk;
}

/* ---------- create VFS inode from ext2 inode number ---------- */

static inode_t* ext2_make_inode(uint32_t ino)
{
    ext2_inode_t disk;
    if (ext2_read_disk_inode(ino, &disk) < 0) return NULL;

    inode_t* inode = create_inode();
    if (!inode) return NULL;

    inode->first_cluster = ino;   /* reuse field for ext2 inode number */
    inode->size   = disk.i_size;
    inode->mode   = disk.i_mode;
    inode->uid    = disk.i_uid;
    inode->gid    = disk.i_gid;
    inode->atime  = disk.i_atime;
    inode->mtime  = disk.i_mtime;
    inode->ctime  = disk.i_ctime;
    inode->blocks = disk.i_blocks;

    if (S_ISDIR(disk.i_mode)) {
        inode->i_op = &ext2_inode_ops;
        inode->f_op = &ext2_dir_ops;
    } else {
        inode->i_op = &ext2_inode_ops;
        inode->f_op = &ext2_file_ops;
    }
    return inode;
}

/* ---------- inode_operations ---------- */

static inode_t* ext2_inode_lookup(inode_t* dir, const char* name)
{
    ext2_inode_t disk;
    if (ext2_read_disk_inode(dir->first_cluster, &disk) < 0) return NULL;

    uint8_t* blkbuf = kmalloc(ext2_fs.block_size);
    if (!blkbuf) return NULL;

    uint8_t  name_len = (uint8_t)strlen(name);
    uint32_t idx;

    /* Walk direct + single-indirect blocks */
    for (idx = 0; idx < 12 + ext2_fs.block_size / 4; idx++) {
        uint32_t blk = ext2_get_block_at(&disk, idx);
        if (blk == 0) break;

        if (ext2_read_block(blk, blkbuf) < 0) break;

        uint32_t offset = 0;
        while (offset + sizeof(ext2_dir_entry_t) <= ext2_fs.block_size) {
            ext2_dir_entry_t* de = (ext2_dir_entry_t*)(blkbuf + offset);
            if (de->rec_len == 0) break;

            if (de->inode != 0 &&
                de->name_len == name_len &&
                memcmp(de->name, name, name_len) == 0) {
                uint32_t found = de->inode;
                kfree(blkbuf);
                return ext2_make_inode(found);
            }
            offset += de->rec_len;
        }
    }

    kfree(blkbuf);
    return NULL;
}

/* ---------- file_operations — open/close ---------- */

static int ext2_file_open(inode_t* inode, file_t* file)
{
    if (!inode || !file) return -EBADF;
    if (S_ISDIR(inode->mode) && ((file->flags & O_ACCMODE) != O_RDONLY))
        return -EISDIR;

    ext2_inode_t* di = kmalloc(sizeof(ext2_inode_t));
    if (!di) return -ENOMEM;

    if (ext2_read_disk_inode(inode->first_cluster, di) < 0) {
        kfree(di);
        return -EIO;
    }
    file->private_data = di;
    file->offset = 0;
    return 0;
}

static int ext2_file_close(file_t* file)
{
    if (!file) return -EBADF;

    if (file->private_data && ext2_valid_disk_inode_ptr((ext2_inode_t*)file->private_data)) {
        kfree(file->private_data);
    }
    file->private_data = NULL;
    return 0;
}

/* ---------- file_operations — regular files ---------- */

static ssize_t ext2_file_read(file_t* file, void* buffer, size_t count)
{
    if (!file || !buffer) return -EBADF;

    ext2_inode_t* di = (ext2_inode_t*)file->private_data;
    if (!ext2_valid_disk_inode_ptr(di)) return -EBADF;

    uint32_t size = di->i_size;
    if (file->offset >= size) return 0;
    if (file->offset + (uint32_t)count > size)
        count = size - file->offset;

    uint8_t* blkbuf = kmalloc(ext2_fs.block_size);
    if (!blkbuf) return -ENOMEM;

    ssize_t  total = 0;
    uint8_t* dst   = (uint8_t*)buffer;

    while (count > 0) {
        uint32_t blk_idx = file->offset / ext2_fs.block_size;
        uint32_t blk_off = file->offset % ext2_fs.block_size;
        uint32_t blk     = ext2_get_block_at(di, blk_idx);

        if (blk == 0) break;
        if (ext2_read_block(blk, blkbuf) < 0) {
            total = total ? total : -EIO;
            break;
        }

        uint32_t chunk = ext2_fs.block_size - blk_off;
        if (chunk > (uint32_t)count) chunk = (uint32_t)count;

        memcpy(dst, blkbuf + blk_off, chunk);
        dst         += chunk;
        file->offset += chunk;
        total        += chunk;
        count        -= chunk;
    }

    kfree(blkbuf);
    return total;
}

static ssize_t ext2_file_write(file_t* file, const void* buffer, size_t count)
{
    if (!file || !buffer) return -EBADF;
    if ((file->flags & O_ACCMODE) == O_RDONLY) return -EBADF;
    if (count == 0) return 0;

    ext2_inode_t* di = (ext2_inode_t*)file->private_data;
    if (!ext2_valid_disk_inode_ptr(di)) return -EBADF;

    uint32_t size = di->i_size;
    if (file->offset >= size) return -ENOSPC;
    if (file->offset + (uint32_t)count > size)
        count = size - file->offset;

    uint8_t* blkbuf = kmalloc(ext2_fs.block_size);
    if (!blkbuf) return -ENOMEM;

    ssize_t total = 0;
    const uint8_t* src = (const uint8_t*)buffer;

    while (count > 0) {
        uint32_t blk_idx = file->offset / ext2_fs.block_size;
        uint32_t blk_off = file->offset % ext2_fs.block_size;
        uint32_t blk = ext2_get_block_at(di, blk_idx);

        if (blk == 0) {
            total = total ? total : -ENOSPC;
            break;
        }

        if (ext2_read_block(blk, blkbuf) < 0) {
            total = total ? total : -EIO;
            break;
        }

        uint32_t chunk = ext2_fs.block_size - blk_off;
        if (chunk > (uint32_t)count) chunk = (uint32_t)count;

        memcpy(blkbuf + blk_off, src, chunk);

        if (ext2_write_block(blk, blkbuf) < 0) {
            total = total ? total : -EIO;
            break;
        }

        src += chunk;
        file->offset += chunk;
        total += chunk;
        count -= chunk;
    }

    kfree(blkbuf);
    return total;
}

static off_t ext2_file_lseek(file_t* file, off_t offset, int whence)
{
    if (!file) return -EBADF;

    ext2_inode_t* di = (ext2_inode_t*)file->private_data;
    if (!ext2_valid_disk_inode_ptr(di)) return -EBADF;

    uint32_t size = di->i_size;
    off_t new_pos;

    switch (whence) {
        case SEEK_SET: new_pos = offset;                       break;
        case SEEK_CUR: new_pos = (off_t)file->offset + offset; break;
        case SEEK_END: new_pos = (off_t)size + offset;         break;
        default:       return -EINVAL;
    }

    if (new_pos < 0) return -EINVAL;
    file->offset = (uint32_t)new_pos;
    return new_pos;
}

/* ---------- file_operations — directories ---------- */

static int ext2_dir_readdir(file_t* file, dirent_t* dirent)
{
    if (!file || !dirent) return -EBADF;

    ext2_inode_t* di = (ext2_inode_t*)file->private_data;
    if (!ext2_valid_disk_inode_ptr(di)) return -EBADF;

    uint32_t dir_size = di->i_size;

    /* file->offset is a byte offset into the directory data */
    if (file->offset >= dir_size) return 0;

    uint8_t* blkbuf = kmalloc(ext2_fs.block_size);
    if (!blkbuf) return -ENOMEM;

    while (file->offset < dir_size) {
        uint32_t blk_idx = file->offset / ext2_fs.block_size;
        uint32_t blk_off = file->offset % ext2_fs.block_size;
        uint32_t blk     = ext2_get_block_at(di, blk_idx);

        if (blk == 0) { file->offset = dir_size; break; }

        if (ext2_read_block(blk, blkbuf) < 0) {
            kfree(blkbuf);
            return -EIO;
        }

        ext2_dir_entry_t* de = (ext2_dir_entry_t*)(blkbuf + blk_off);

        if (de->rec_len == 0) {
            /* Advance to next block */
            file->offset = (blk_idx + 1) * ext2_fs.block_size;
            continue;
        }

        file->offset += de->rec_len;

        if (de->inode == 0) continue; /* deleted entry */

        /* Fill dirent */
        dirent->d_ino = de->inode;
        dirent->d_type = (de->file_type == EXT2_FT_DIR) ? DT_DIR : DT_REG;
        uint8_t nlen = de->name_len;
        memcpy(dirent->d_name, de->name, nlen);
        dirent->d_name[nlen] = '\0';
        dirent->d_reclen = sizeof(dirent_t);

        kfree(blkbuf);
        return 1;
    }

    kfree(blkbuf);
    return 0;
}

/* ---------- mount ---------- */

inode_t* ext2_mount(uint64_t lba_start)
{
    /* Superblock is at byte offset 1024 = LBA offset 2 (512-byte sectors) */
    ext2_superblock_t* sb = kmalloc(1024);
    if (!sb) return NULL;

    if (blk_read_sectors(lba_start + 2, 2, sb) < 0) {
        KERROR("[EXT2] Cannot read superblock at LBA %llu\n",
               (unsigned long long)(lba_start + 2));
        kfree(sb);
        return NULL;
    }

    if (sb->s_magic != EXT2_MAGIC) {
        KERROR("[EXT2] Bad magic: 0x%X (expected 0x%X)\n", sb->s_magic, EXT2_MAGIC);
        kfree(sb);
        return NULL;
    }

    ext2_fs.lba_start         = lba_start;
    ext2_fs.block_size        = 1024u << sb->s_log_block_size;
    ext2_fs.sectors_per_block = ext2_fs.block_size / 512;
    ext2_fs.inodes_per_group  = sb->s_inodes_per_group;
    ext2_fs.blocks_per_group  = sb->s_blocks_per_group;
    ext2_fs.inode_size        = (sb->s_rev_level >= 1) ? sb->s_inode_size : 128;
    /* Group descriptor table starts right after the superblock's block */
    ext2_fs.gdesc_block       = sb->s_first_data_block + 1;
    ext2_fs.mounted           = true;

    KINFO("[EXT2] Mounted: block_size=%u inodes_per_group=%u inode_size=%u gdesc_block=%u\n",
          ext2_fs.block_size, ext2_fs.inodes_per_group,
          ext2_fs.inode_size, ext2_fs.gdesc_block);

    kfree(sb);
    return ext2_make_inode(EXT2_ROOT_INO);
}
