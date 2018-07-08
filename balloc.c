#include <linux/fs.h>
#include <linux/slab.h>

#include "aeon.h"


int aeon_alloc_block_free_lists(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	int i;

	sbi->free_lists = kcalloc(sbi->cpus, sizeof(struct free_list), GFP_KERNEL);

	if(!sbi->free_lists)
		return -ENOMEM;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		free_list->block_free_tree = RB_ROOT;
		spin_lock_init(&free_list->s_lock);
		free_list->index = i;
	}

	return 0;
}

void aeon_delete_free_lists(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	/* Each tree is freed in save_blocknode_mappings */
	kfree(sbi->free_lists);
}

static int aeon_insert_blocktree(struct rb_root *tree, struct aeon_range_node *new_node)
{
	int ret;

	ret = aeon_insert_range_node(tree, new_node, NODE_BLOCK);
	if (ret)
		aeon_dbg("ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

static void aeon_init_free_list(struct super_block *sb, struct free_list *free_list, int index)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long per_list_blocks;

	per_list_blocks = sbi->num_blocks / sbi->cpus;

	free_list->block_start = per_list_blocks * index;
	free_list->block_end = free_list->block_start + per_list_blocks - 1;
}

void aeon_init_blockmap(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct rb_root *tree;
	struct free_list *free_list;
	struct aeon_range_node *blknode;
	int ret;
	int i;

	sbi->per_list_blocks = sbi->num_blocks / sbi->cpus;
	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		tree = &(free_list->block_free_tree);
		aeon_init_free_list(sb, free_list, i);

		free_list->num_free_blocks = free_list->block_end - free_list->block_start + 1;

		blknode = aeon_alloc_block_node(sb);
		if (i == 0)
			blknode->range_low = free_list->block_start + 1;
		else
			blknode->range_low = free_list->block_start;
		blknode->range_high = free_list->block_end;
		ret = aeon_insert_blocktree(tree, blknode);
		if (ret) {
			aeon_err(sb, "%s failed\n", __func__);
			aeon_free_block_node(blknode);
			return;
		}
		free_list->first_node = blknode;
		free_list->last_node = blknode;
		free_list->num_blocknode = 1;

		aeon_dbg("%s: free list %d: block start %lu, end %lu, %lu free blocks\n",
			 __func__, i,
			 free_list->block_start,
			 free_list->block_end,
			 free_list->num_free_blocks);
	}
}

static inline int aeon_rbtree_compare_rangenode(struct aeon_range_node *curr, unsigned long key, enum node_type type)
{
	if (type == NODE_DIR) {
		if (key < curr->hash)
			return -1;
		if (key > curr->hash)
			return 1;
		return 0;
	}

	/* Block and inode */
	if (key < curr->range_low)
		return -1;
	if (key > curr->range_high)
		return 1;

	return 0;
}

int aeon_insert_range_node(struct rb_root *tree, struct aeon_range_node *new_node, enum node_type type)
{
	struct aeon_range_node *curr;
	struct rb_node **temp, *parent;
	int compVal;

	temp = &(tree->rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct aeon_range_node, node);
		compVal = aeon_rbtree_compare_rangenode(curr, new_node->range_low, type);

		parent = *temp;

		if (compVal == -1)
			temp = &((*temp)->rb_left);
		else if (compVal == 1)
			temp = &((*temp)->rb_right);
		else {
			aeon_dbg("%s: type %d entry %lu - %lu already exists: "
				"%lu - %lu\n",
				 __func__, type, new_node->range_low,
				new_node->range_high, curr->range_low,
				curr->range_high);
			return -EINVAL;
		}

	}

	rb_link_node(&new_node->node, parent, temp);
	rb_insert_color(&new_node->node, tree);

	return 0;
}

int aeon_find_range_node(struct rb_root *tree, unsigned long key,
	enum node_type type, struct aeon_range_node **ret_node)
{
	struct aeon_range_node *curr = NULL;
	struct rb_node *temp;
	int compVal;
	int ret = 0;

	temp = tree->rb_node;

	while (temp) {
		curr = container_of(temp, struct aeon_range_node, node);
		compVal = aeon_rbtree_compare_rangenode(curr, key, type);

		if (compVal == -1)
			temp = temp->rb_left;
		else if (compVal == 1)
			temp = temp->rb_right;
		else {
			ret = 1;
			break;
		}
	}

	*ret_node = curr;
	return ret;
}

static int not_enough_blocks(struct free_list *free_list, unsigned long num_blocks)
{
	struct aeon_range_node *first = free_list->first_node;
	struct aeon_range_node *last = free_list->last_node;

	aeon_dbg("%s\n", __func__);
	if (free_list->num_free_blocks < num_blocks || !first || !last) {
		aeon_dbg("%s: num_free_blocks=%ld; num_blocks=%ld; first=0x%p; last=0x%p",
			 __func__, free_list->num_free_blocks, num_blocks,
			 first, last);
		return 1;
	}

	return 0;
}

/* Return how many blocks allocated */
static long aeon_alloc_blocks_in_free_list(struct super_block *sb, struct free_list *free_list,
		unsigned short btype, unsigned long num_blocks, unsigned long *new_blocknr)
{
	struct rb_root *tree;
	struct aeon_range_node *curr, *next = NULL, *prev = NULL;
	struct rb_node *temp, *next_node, *prev_node;
	unsigned long curr_blocks;
	bool found = 0;
	unsigned long step = 0;

	if (!free_list->first_node || free_list->num_free_blocks == 0) {
		aeon_dbg("%s: Can't alloc. free_list->first_node=0x%p free_list->num_free_blocks = %lu",
			  __func__, free_list->first_node,
			  free_list->num_free_blocks);
		return -ENOSPC;
	}

	tree = &(free_list->block_free_tree);
	temp = &(free_list->first_node->node);

	while (temp) {
		step++;
		curr = container_of(temp, struct aeon_range_node, node);

		curr_blocks = curr->range_high - curr->range_low + 1;

		if (num_blocks >= curr_blocks) {
			/* Superpage allocation must succeed */
			if (btype > 0 && num_blocks > curr_blocks)
				goto next;

			/* Otherwise, allocate the whole blocknode */
			if (curr == free_list->first_node) {
				next_node = rb_next(temp);
				if (next_node)
					next = container_of(next_node, struct aeon_range_node, node);
				free_list->first_node = next;
			}

			if (curr == free_list->last_node) {
				prev_node = rb_prev(temp);
				if (prev_node)
					prev = container_of(prev_node, struct aeon_range_node, node);
				free_list->last_node = prev;
			}

			rb_erase(&curr->node, tree);
			free_list->num_blocknode--;
			num_blocks = curr_blocks;
			*new_blocknr = curr->range_low;
			aeon_free_block_node(curr);
			found = 1;
			break;
		}

		/* Allocate partial blocknode */
		*new_blocknr = curr->range_low;
		curr->range_low += num_blocks;

		found = 1;
		break;
next:
		temp = rb_next(temp);
	}

	if (free_list->num_free_blocks < num_blocks) {
		aeon_dbg("%s: free list %d has %lu free blocks, but allocated %lu blocks?\n",
				__func__, free_list->index,
				free_list->num_free_blocks, num_blocks);
		return -ENOSPC;
	}

	if (found == 1)
		free_list->num_free_blocks -= num_blocks;
	else {
		aeon_dbg("%s: Can't alloc.  found = %d", __func__, found);
		return -ENOSPC;
	}

	aeon_dbg("%s: %lu : %lu\n", __func__, curr->range_low, curr->range_high);

	return num_blocks;

}

/* Find out the free list with most free blocks */
static int aeon_get_candidate_free_list(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	int cpuid = 0;
	int num_free_blocks = 0;
	int i;

	aeon_dbg("%s\n", __func__);
	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		if (free_list->num_free_blocks > num_free_blocks) {
			cpuid = i;
			num_free_blocks = free_list->num_free_blocks;
		}
	}

	return cpuid;
}

static int aeon_new_blocks(struct super_block *sb, unsigned long *blocknr,
	unsigned int num, unsigned short btype, int cpuid)
{
	struct free_list *free_list;
	unsigned long num_blocks = 0;
	unsigned long new_blocknr = 0;
	long ret_blocks = 0;
	int retried = 0;

	aeon_dbg("%s\n", __func__);
	num_blocks = num * aeon_get_numblocks(btype);

	if (cpuid == ANY_CPU)
		cpuid = aeon_get_cpuid(sb);

retry:
	free_list = aeon_get_free_list(sb, cpuid);
	spin_lock(&free_list->s_lock);

	if (not_enough_blocks(free_list, num_blocks)) {
		aeon_dbg("%s: cpu %d, free_blocks %lu, required %lu, blocknode %lu\n",
			 __func__, cpuid, free_list->num_free_blocks,
			 num_blocks, free_list->num_blocknode);

		if (retried >= 2)
			goto alloc;

		spin_unlock(&free_list->s_lock);
		cpuid = aeon_get_candidate_free_list(sb);
		retried++;
		goto retry;
	}

alloc:
	ret_blocks = aeon_alloc_blocks_in_free_list(sb, free_list, btype, num_blocks, &new_blocknr);

	if (ret_blocks > 0) {
		free_list->alloc_data_count++;
		free_list->alloc_data_pages += ret_blocks;
	}

	spin_unlock(&free_list->s_lock);

	if (ret_blocks <= 0 || new_blocknr == 0) {
		aeon_dbg("%s: not able to allocate %d blocks.  ret_blocks=%ld; new_blocknr=%lu",
				 __func__, num, ret_blocks, new_blocknr);
		return -ENOSPC;
	}

	*blocknr = new_blocknr;

	return ret_blocks / aeon_get_numblocks(btype);
}

// Allocate data blocks.  The offset for the allocated block comes back in
// blocknr.  Return the number of blocks allocated.
static int aeon_new_data_blocks(struct super_block *sb,
	struct aeon_inode_info_header *sih, unsigned long *blocknr,
	unsigned long start_blk, unsigned int num, int cpu)
{
	int allocated;

	aeon_dbg("%s\n", __func__);

	allocated = aeon_new_blocks(sb, blocknr, num,
			    sih->i_blk_type, cpu);

	if (allocated < 0) {
		aeon_dbg("FAILED: Inode %lu, start blk %lu, alloc %d data blocks from %lu to %lu\n",
			  sih->ino, start_blk, allocated, *blocknr,
			  *blocknr + allocated - 1);
	} else {
		aeon_dbg("Inode %lu, start blk %lu, alloc %d data blocks from %lu to %lu\n",
			  sih->ino, start_blk, allocated, *blocknr,
			  *blocknr + allocated - 1);
	}
	return allocated;
}

static int aeon_find_data_blocks(struct aeon_inode *pi, unsigned long *bno, int *num_blocks)
{
	if (pi->num_pages == 0)
		return 0;

	*bno = pi->block;
	*num_blocks = pi->num_pages;

	return 1;
}

/*
 * return > 0, # of blocks mapped or allocated.
 * return = 0, if plain lookup failed.
 * return < 0, error case.
 */
int aeon_dax_get_blocks(struct inode *inode, unsigned long iblock,
	unsigned long max_blocks, u32 *bno, bool *new, bool *boundary, int create)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pi;
	unsigned long blocknr = 0;
	int num_blocks = 1;
	int allocated;
	int found;

	pi = aeon_get_inode(sb, inode);
	inode->i_ctime = inode->i_mtime = current_time(inode);

	found = aeon_find_data_blocks(pi, &blocknr, &num_blocks);
	if (found) {
		*bno = blocknr;
		if (iblock == 0) {
			aeon_dbg("%s: retunr num_blocks\n", __func__);
			return num_blocks;
		}
	}

	if (create == 0) {
		/* return page offset */
		aeon_dbg("%s: create == 0\n", __func__);
		return num_blocks;
	}

	/* Return initialized blocks to the user */
	allocated = aeon_new_data_blocks(sb, sih, &blocknr, iblock, num_blocks, ANY_CPU);
	aeon_dbg("%s: allocated - %d, blocknr - %lu, num_blocks - %d\n", __func__, allocated, blocknr, num_blocks);
	*bno = blocknr;

	pi->num_pages = num_blocks;
	pi->block = blocknr;

	return allocated;
}

// Allocate inode block.  The offset for the allocated block comes back in
// blocknr.  Return the number of blocks allocated (should be 1).
int aeon_get_new_inode_block(struct super_block *sb, u64 *pi_addr, int cpuid)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long allocated;
	unsigned long blocknr = 0;
	int num_blocks = 1;

	allocated = aeon_new_blocks(sb, &blocknr, num_blocks, 0, cpuid);

	sbi->inode_maps[cpuid].virt_addr = (void *)(blocknr * AEON_DEF_BLOCK_SIZE_4K + (u64)sbi->virt_addr);

	aeon_dbg("%s: blocknr %lu, pi_addr %llx\n", __func__, blocknr, (u64)sbi->inode_maps[cpuid].virt_addr);

	return allocated;
}

// Allocate dentry block.  The offset for the allocated block comes back in
// blocknr.  Return the number of blocks allocated (should be 1).
u64 aeon_get_new_dentry_block(struct super_block *sb, u64 *pi_addr, unsigned long *blocknr, int cpuid)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long allocated;

	allocated = aeon_new_blocks(sb, blocknr, 1, 0, ANY_CPU);

	*pi_addr = (u64)sbi->virt_addr + *blocknr * AEON_DEF_BLOCK_SIZE_4K;

	aeon_dbg("%s: blocknr %lu, pi_addr %llx\n", __func__, *blocknr, *pi_addr);

	return *pi_addr;
}
