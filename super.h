#ifndef __AEON_SUPER_H
#define __AEON_SUPER_H

#include "aeon.h"

static inline struct aeon_sb_info *AEON_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

/*
 * Get the persistent memory's address
 */
static inline struct aeon_super_block *aeon_get_super(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return (struct aeon_super_block *)sbi->virt_addr;
}

/* Translate an offset the beginning of the aeon instance to a PMEM address.
 *
 * If this is part of a read-modify-write of the block,
 * aeon_memunlock_block() before calling!
 */
static inline void *aeon_get_block(struct super_block *sb, u64 block)
{
	struct aeon_super_block *ps = aeon_get_super(sb);

	return block ? ((void *)ps + block) : NULL;
}

static inline int aeon_get_reference(struct super_block *sb, u64 block,
		void *dram, void **nvmm, size_t size)
{
	int rc = 0;

	*nvmm = aeon_get_block(sb, block);
	aeon_dbg("%s: nvmm 0x%lx\n", __func__, (unsigned long)*nvmm);
	rc = memcpy_mcsafe(dram, *nvmm, size);
	return rc;
}

struct aeon_range_node *aeon_alloc_inode_node(struct super_block *);
void aeon_free_inode_node(struct aeon_range_node *node);
void aeon_free_dir_node(struct aeon_range_node *node);
struct aeon_range_node *aeon_alloc_dir_node(struct super_block *sb);

#endif
