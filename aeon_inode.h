#ifndef __AEON_INODE_H
#define __AEON_INODE_H

#define AEON_INODE_SIZE         (1 << AEON_I_SHIFT)
#define AEON_INODE_CSIZE        (AEON_INODE_SIZE - CHECKSUM_SIZE)
#define AEON_I_NUM_PER_PAGE     ((AEON_DEF_BLOCK_SIZE_4K / AEON_INODE_SIZE) * \
						AEON_PAGES_FOR_INODE)

/*
 * extent tree's header referred from inode
 */
#define PI_MAX_INTERNAL_EXTENT 5
#define PI_MAX_EXTERNAL_EXTENT 3

struct imem_cache {
	u32	ino;
	u64	addr;
	int	independent;
	struct	imem_cache *head;
	struct	list_head imem_list;
};

struct i_valid_list {
	u32	parent_ino;
	u64	addr;
	struct	i_valid_child_list *ivcl;
	struct	list_head i_valid_list;
};

struct i_valid_child_list {
	u32	ino;
	u64	addr;
	u32	parent_ino;
	struct	list_head i_valid_child_list;
};

struct aeon_extent_header {
	__le16  eh_entries;
	__le16  eh_depth;
	__le64  eh_extent_blocks[PI_MAX_EXTERNAL_EXTENT];
	__le32  eh_blocks;
} __attribute((__packed__));

struct aeon_extent {
	__le16	ex_index;
	__le64  ex_block;
	__le16  ex_length;
	__le32  ex_offset;
} __attribute((__packed__));

enum aeon_new_inode_type {
	TYPE_CREATE = 0,
	TYPE_MKNOD,
	TYPE_SYMLINK,
	TYPE_MKDIR
};

/*
 * Structure of an inode in AEON on pmem.
 */
struct aeon_inode {
	/* first 40 bytes */
	u8	valid;		 /* Is this inode valid? */
	u8	compressed;	 /* Is this file compressed? */
	u8	deleted;	 /* Is this inode deleted? */
	u8	i_new;           /* Is this inode new? */
	/* 4  */
	__le32	i_flags;	 /* Inode flags */
	__le64	i_size;		 /* Size of data in bytes */
	__le32	i_ctime;	 /* Inode modification time */
	__le32	i_mtime;	 /* Inode tree Modification time */
	__le32	i_atime;	 /* Access time */
	__le16	i_mode;		 /* File mode */
	__le64	i_links_count;	 /* Links count */

	__le64	i_xattr;	 /* Extended attribute block */

	/* second 40 bytes */
	__le32	i_uid;		 /* Owner Uid */
	__le32	i_gid;		 /* Group Id */
	__le32	i_generation;	 /* File version (for NFS) */
	__le32	i_create_time;	 /* Create time */
	__le32	aeon_ino;	 /* aeon inode number */
	__le32	parent_ino;	 /* parent inode number */

	__le64	i_pinode_addr;	 /* parent inode address offset */
	__le64	i_dentry_addr;	 /* A related dentry address offset */
	__le64	i_inode_addr;	 /* inode itself address offset */

	__le64	i_next_inode_block;
	__le64	i_dentry_table_block;

	__le64  i_block;         /* exist extent or point extent block */
	__le64	i_blocks;        /* block counts */
	__le64	sym_block;	 /* for symbolic link */

	struct {
		__le32 rdev;	 /* major/minor # */
	} dev;			 /* device inode */

	struct aeon_extent_header aeh;
	struct aeon_extent ae[PI_MAX_INTERNAL_EXTENT];
	__le16 i_exblocks;

	__le32	csum;            /* CRC32 checksum */
} __attribute((__packed__));


/*
 * Structure of an inode in AEON on DRAM.
 */
struct aeon_inode_info_header {
	/* Map from file offsets to write log entries. */
	struct     aeon_dentry_info *de_info;
	struct     rb_root rb_tree;		/* RB tree for directory or extent*/
	struct     rw_semaphore dax_sem;
	struct     rw_semaphore xattr_sem;
	struct     mutex truncate_mutex;
	int	   num_vmas;
	u64	   pi_addr;
	u8	   i_blk_type;
	spinlock_t i_exlock;
	rwlock_t   i_meta_lock;
};

struct aeon_inode_info {
	struct aeon_inode_info_header header;
	struct inode vfs_inode;
};

static inline struct aeon_inode_info *AEON_I(struct inode *inode)
{
	return container_of(inode, struct aeon_inode_info, vfs_inode);
}

#include "aeon_super.h"

static inline
u64 aeon_get_reserved_inode_addr(struct super_block *sb, u64 inode_number)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return aeon_get_addr_off(sbi) + AEON_SB_SIZE +
		(inode_number % 32 - 1) * AEON_INODE_SIZE;
}

static inline
struct aeon_inode *aeon_get_reserved_inode(struct super_block *sb, u64 ino)
{
	return (struct aeon_inode *)aeon_get_reserved_inode_addr(sb, ino);
}

static inline
struct aeon_inode *aeon_get_reserved_inode_ino(struct super_block *sb, u64 ino)
{
	if (ino == 0)
		return NULL;
	return (struct aeon_inode *)aeon_get_reserved_inode_addr(sb, ino);
}

static inline
struct aeon_inode *aeon_get_inode(struct super_block *sb,
				  struct aeon_inode_info_header *sih)
{
	struct aeon_inode fake_pi;
	void *addr;
	int rc;

	addr = (void *)sih->pi_addr;
	rc = memcpy_mcsafe(&fake_pi, addr, sizeof(struct aeon_inode));
	if (rc) {
		aeon_err(sb, "%s: ERROR\n", __func__);
		return NULL;
	}

	return (struct aeon_inode *)addr;
}

/*
 * This function only is called from ioctl.c for the purpose of
 * file system test so far.
 */
static inline
struct aeon_inode *aeon_get_pinode(struct super_block *sb,
				   struct aeon_inode_info_header *sih)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode *pi;
	u64 addr;

	pi = aeon_get_inode(sb, sih);
	addr = (u64)sbi->virt_addr + le64_to_cpu(pi->i_pinode_addr);

	return (struct aeon_inode *)addr;
}

static inline int is_persisted_inode(struct aeon_inode *pi)
{
	__le32 temp;

	temp = cpu_to_le32(crc32_le(SEED,
				    (unsigned char *)pi,
				    AEON_INODE_CSIZE));
	if (temp != pi->csum)
		return 0;

	return 1;
}

static inline void aeon_update_inode_csum(struct aeon_inode *pi)
{
	pi->csum = cpu_to_le32(crc32_le(SEED,
					(unsigned char *)pi,
					AEON_INODE_CSIZE));
}


int aeon_init_inode_inuse_list(struct super_block *sb);
int aeon_get_inode_address(struct super_block *sb,
			   u32 ino, u64 *pi_addr, struct aeon_dentry *de);
u32 aeon_inode_by_name(struct inode *dir, struct qstr *entry);
void aeon_set_file_ops(struct inode *inode);
struct inode *aeon_new_vfs_inode(enum aeon_new_inode_type type,
				 struct inode *dir, u64 pi_addr, u64 de_addr,
				 u32 ino, umode_t mode, struct aeon_inode *pidir,
				 size_t size, dev_t rdev);
u32 aeon_new_aeon_inode(struct super_block *sb, u64 *pi_addr);
void aeon_set_inode_flags(struct inode *inode, struct aeon_inode *pi,
			  unsigned int flags);
struct inode *aeon_iget(struct super_block *sb, u32 ino);
int aeon_free_inode_resource(struct super_block *sb, struct aeon_inode *pi,
			     struct aeon_inode_info_header *sih);
int aeon_free_dram_resource(struct super_block *sb,
			    struct aeon_inode_info_header *sih);
void aeon_destroy_imem_cache(struct inode_map *inode_map);
int aeon_update_time(struct inode *inode, struct timespec64 *time, int flags);
void aeon_truncate_blocks(struct inode *inode, loff_t offset);
int aeon_setattr(struct dentry *dentry, struct iattr *iattr);

#endif
