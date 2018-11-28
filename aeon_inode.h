#ifndef __AEON_INODE_H
#define __AEON_INODE_H

/*
 * extent tree's header referred from inode
 */
#define PI_MAX_INTERNAL_EXTENT 5
#define PI_MAX_EXTERNAL_EXTENT 3

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
	u8	persisted;	 /* Is this inode persistent? */
	u8	valid;		 /* Is this inode valid? */
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
	u8      i_internal_allocated;

	__le64  i_block;         /* exist extent or point extent block */
	__le64	i_blocks;        /* block counts */
	__le64	sym_block;	 /* for symbolic link */

	struct {
		__le32 rdev;	 /* major/minor # */
	} dev;			 /* device inode */

	struct aeon_extent_header aeh;
	struct aeon_extent ae[PI_MAX_INTERNAL_EXTENT];
	__le16 i_exblocks;

	char	pad[7];
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
int aeon_update_time(struct inode *inode, struct timespec64 *time, int flags);
void aeon_truncate_blocks(struct inode *inode, loff_t offset);
int aeon_setattr(struct dentry *dentry, struct iattr *iattr);

#endif
