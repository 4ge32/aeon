#ifndef __AEON_INODE_H
#define __AEON_INODE_H

#include "aeon.h"

enum aeon_new_inode_type {
	TYPE_CREATE = 0,
	TYPE_MKNOD,
	TYPE_SYMLINK,
	TYPE_MKDIR
};

/* inode.h */
struct aeon_inode_info_header {
	/* Map from file offsets to write log entries. */
	struct radix_tree_root tree;
	struct rb_root rb_tree;		/* RB tree for directory */
	struct rb_root vma_tree;	/* Write vmas */
	struct list_head list;		/* SB list of mmap sih */
	int num_vmas;
	unsigned short i_mode;		/* Dir or file? */
	unsigned int i_flags;
	unsigned long i_size;
	unsigned long i_blocks;
	unsigned long ino;
	unsigned long pi_addr;
	unsigned long alter_pi_addr;
	unsigned long valid_entries;	/* For thorough GC */
	unsigned long num_entries;	/* For thorough GC */
	u64 last_setattr;		/* Last setattr entry */
	u64 last_link_change;		/* Last link change entry */
	u64 last_dentry;		/* Last updated dentry */
	u8  i_blk_type;
	struct aeon_inode *pi;
};

struct aeon_inode_info {
	struct aeon_inode_info_header header;
	struct inode vfs_inode;
};

static inline struct aeon_inode_info *AEON_I(struct inode *inode)
{
	return container_of(inode, struct aeon_inode_info, vfs_inode);
}

static inline u64 aeon_get_addr_off(struct aeon_sb_info *sbi) {
	return (u64)sbi->virt_addr;
}

static inline u64 aeon_get_reserved_inode_addr(struct super_block *sb, u64 inode_number)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return aeon_get_addr_off(sbi) + AEON_DEF_BLOCK_SIZE_4K
		+ (inode_number % 32 - 1) * AEON_INODE_SIZE;
}

static inline struct aeon_inode *aeon_get_reserved_inode(struct super_block *sb, u64 inode_number)
{
	u64 addr;

	addr = aeon_get_reserved_inode_addr(sb, inode_number);
	aeon_dbg("%s : 0x%lx\n", __func__, (unsigned long)addr);

	return (struct aeon_inode *)addr;
}

static inline struct aeon_inode *aeon_get_inode_by_ino(struct super_block *sb, u64 ino)
{
	if (ino == 0)
		return NULL;
	return aeon_get_reserved_inode(sb, ino);
}

static inline struct aeon_inode *aeon_get_inode(struct super_block *sb, struct inode *inode)
{
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode fake_pi;
	void *addr;
	int rc;

	addr = aeon_get_block(sb, sih->pi_addr);
	rc = memcpy_mcsafe(&fake_pi, addr, sizeof(struct aeon_inode));
	if (rc) {
		aeon_err(sb, "%s: ERROR\n", __func__);
		return NULL;
	}

	return (struct aeon_inode *)addr;
}

static inline void aeon_init_header(struct super_block *sb, struct aeon_inode_info_header *sih, u16 i_mode)
{
	sih->i_size = 0;
	sih->ino = 0;
	sih->i_blocks = 0;
	sih->pi_addr = 0;
	sih->alter_pi_addr = 0;
	INIT_RADIX_TREE(&sih->tree, GFP_ATOMIC);
	sih->rb_tree = RB_ROOT;
	sih->vma_tree = RB_ROOT;
	sih->num_vmas = 0;
	INIT_LIST_HEAD(&sih->list);
	sih->i_mode = i_mode;
	sih->i_flags = 0;
	sih->valid_entries = 0;
	sih->num_entries = 0;
	sih->last_setattr = 0;
	sih->last_link_change = 0;
	sih->last_dentry = 0;
}


extern const struct address_space_operations aeon_aops_dax;
int aeon_init_inode_inuse_list(struct super_block *);
int aeon_init_inode_table(struct super_block *);
struct inode *aeon_iget(struct super_block *, unsigned long);
u64 aeon_new_aeon_inode(struct super_block *, u64 *);
int aeon_get_inode_address(struct super_block *, u64 ino, u64 *pi_addr);
struct inode *aeon_new_vfs_inode(enum aeon_new_inode_type type,
	struct inode *dir, u64 pi_addr, u64 ino, umode_t mode,
	size_t size, dev_t rdev, const struct qstr *qstr);
ino_t aeon_inode_by_name(struct inode *dir, struct qstr *entry);

#endif
