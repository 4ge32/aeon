#ifndef __AEON_BALLOC_H
#define __AEON_BALLOC_H

#include "inode.h"

struct free_list {
	spinlock_t s_lock;
	struct rb_root	block_free_tree;
	struct aeon_range_node *first_node; // lowest address free range
	struct aeon_range_node *last_node; // highest address free range

	int		index; // Which CPU do I belong to?

	/* Where are the data checksum blocks */
	unsigned long	csum_start;
	unsigned long	replica_csum_start;
	unsigned long	num_csum_blocks;

	/* Where are the data parity blocks */
	unsigned long	parity_start;
	unsigned long	replica_parity_start;
	unsigned long	num_parity_blocks;

	/* Start and end of allocatable range, inclusive. Excludes csum and
	 * parity blocks.
	 */
	unsigned long	block_start;
	unsigned long	block_end;

	unsigned long	num_free_blocks;

	/* How many nodes in the rb tree? */
	unsigned long	num_blocknode;

	u32		csum;		/* Protect integrity */

	/* Statistics */
	unsigned long	alloc_data_count;
	unsigned long	free_data_count;
	unsigned long	alloc_data_pages;
	unsigned long	freed_data_pages;

	u64		padding[8];	/* Cache line break */
};

enum node_type {
	NODE_BLOCK = 1,
	NODE_INODE,
	NODE_DIR,
};

static inline struct free_list *aeon_get_free_list(struct super_block *sb, int cpu)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return &sbi->free_lists[cpu];
}

int aeon_alloc_block_free_lists(struct super_block *);
void aeon_init_blockmap(struct super_block *);
int aeon_insert_range_node(struct rb_root *, struct aeon_range_node *, enum node_type);
void aeon_delete_free_lists(struct super_block *sb);
int aeon_find_range_node(struct rb_root *tree, unsigned long key,
	enum node_type type, struct aeon_range_node **ret_node);

#endif
