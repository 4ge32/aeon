#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/rwlock.h>

#include "aeon.h"
#include "aeon_super.h"
#include "aeon_extents.h"
#include "aeon_balloc.h"

#ifdef CONFIG_AEON_FS_NUMA
int aeon_alloc_block_free_lists(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	struct numa_maps *nm;
	int numa_id;
	int cpu_id;

	sbi->nm = aeon_alloc_numa_maps(sb);
	if (!sbi->nm)
		return -ENOMEM;


	for (numa_id = 0; numa_id < sbi->numa_nodes; numa_id++) {
		sbi->nm[numa_id].free_lists = aeon_alloc_free_lists(sb);
		if (!sbi->nm->free_lists)
			return -ENOMEM;
	}

	for (numa_id = 0; numa_id < sbi->numa_nodes; numa_id++) {
		int list_id = 0;

		nm = &sbi->nm[numa_id];
		nm->map_id = 0;
		nm->max_id = sbi->cpus/sbi->numa_nodes;
		nm->numa_id = numa_id;

		for (cpu_id = 0; cpu_id < sbi->cpus; cpu_id++) {
			if (cpu_to_mem(cpu_id) != numa_id)
				continue;

			free_list  = &sbi->nm[numa_id].free_lists[list_id++];
			free_list->block_free_tree = RB_ROOT;
			spin_lock_init(&free_list->s_lock);
			free_list->index = cpu_id;
			free_list->numa_index = numa_id;
		}
	}

	for (numa_id = 0; numa_id < sbi->numa_nodes; numa_id++) {
		int list_id = 0;

		nm = &sbi->nm[numa_id];

		for (cpu_id = 0; cpu_id < sbi->cpus; cpu_id++) {
			if (cpu_to_mem(cpu_id) != numa_id)
				continue;

			aeon_dbgv("%d,%d,%d numa %d cpuid %d\n",
				  numa_id, cpu_id,
				  nm->numa_id,
				  nm->free_lists[list_id].numa_index,
				  nm->free_lists[list_id].index);
			list_id++;
		}
	}

	return 0;
}
#else
int aeon_alloc_block_free_lists(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	int i;

	sbi->free_lists = aeon_alloc_free_lists(sb);
	if (!sbi->free_lists)
		return -ENOMEM;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		free_list->block_free_tree = RB_ROOT;
		spin_lock_init(&free_list->s_lock);
		free_list->index = i;
	}

	return 0;
}
#endif

static void
do_aeon_save_block_range_nodes(struct super_block *sb, struct rb_root *tree,
			       int cpu_id, int num_nodes)
{
	struct aeon_range_node *curr;
	struct rb_node *temp;
	struct aeon_region_table *art = aeon_get_rtable(sb, cpu_id);
	u64 start_addr = (u64)art + AEON_INODE_SIZE;
	__le32 *range_low;
	__le32 *range_high;
	int count = 0;

	art->range_nodes = le16_to_cpu(num_nodes);

	temp = rb_first(tree);
	while (temp) {
		curr = container_of(temp, struct aeon_range_node, node);
		temp = rb_next(temp);

		range_low = (__le32 *)(start_addr + count * 32);
		range_high = range_low + 1;

		*range_low = curr->range_low;
		*range_high = curr->range_high;

		count += 2;
	}
}

/* 4k page - aeon_region_table */
#define MAX_NODES (AEON_DEF_BLOCK_SIZE_4K - AEON_INODE_SIZE) / 32
static void aeon_save_free_lists(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	struct rb_root *tree;
	struct aeon_range_node *curr;
	struct rb_node *temp;
	int i;
	int num_nodes = 0;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		tree = &free_list->block_free_tree;

		temp = rb_first(tree);
		while (temp) {
			curr = container_of(temp, struct aeon_range_node, node);
			temp = rb_next(temp);

			num_nodes += 2;
		}

		if (num_nodes < MAX_NODES)
			do_aeon_save_block_range_nodes(sb, tree, i, num_nodes);
		else
			BUG(); /*TODO expand it */

		num_nodes = 0;
	}
}

void aeon_delete_free_lists(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	struct rb_root *disposal;
	int i;

	aeon_save_free_lists(sb);

	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		disposal = &free_list->block_free_tree;
		aeon_destroy_range_node_tree(sb, disposal);
		free_list->first_node = NULL;
		free_list->last_node = NULL;

	}
	aeon_free_free_lists(sb);
	sbi->free_lists = NULL;
}

unsigned long aeon_count_free_blocks(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	unsigned long num_free_blocks = 0;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		num_free_blocks += free_list->num_free_blocks;
	}

	return num_free_blocks;
}

static int aeon_insert_blocktree(struct rb_root *tree,
				 struct aeon_range_node *new_node)
{
	int ret;

	ret = aeon_insert_range_node(tree, new_node, NODE_BLOCK);
	if (ret)
		aeon_dbg("ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

static void aeon_init_free_list(struct super_block *sb,
				struct free_list *free_list, int index)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long per_list_blocks;

	per_list_blocks = sbi->num_blocks / sbi->cpus;

	free_list->block_start = per_list_blocks * index;
	free_list->block_end = free_list->block_start + per_list_blocks - 1;

	sbi->last_addr = free_list->block_end << AEON_SHIFT;
}

static void do_aeon_rebuild_blockmap(struct super_block *sb, int cpu_id,
				     u64 start_addr, int num_nodes)
{
	struct free_list *free_list;
	struct aeon_range_node *blknode;
	struct rb_root *tree;
	int offset = 0;
	int ret;
	__le32 *range_low;
	__le32 *range_high;

	free_list = aeon_get_free_list(sb, cpu_id);
	tree = &(free_list->block_free_tree);
	aeon_init_free_list(sb, free_list, cpu_id);

	for (offset = 0; offset < num_nodes; offset+=2) {
		range_low = (__le32 *)(start_addr + offset * 32);
		range_high = (__le32 *)(range_low + 1);

		blknode = aeon_alloc_block_node(sb);
		blknode->range_low = le32_to_cpu(*range_low);
		blknode->range_high = le32_to_cpu(*range_high);

		ret = aeon_insert_blocktree(tree, blknode);
		if (ret) {
			aeon_err(sb, "%s failed\n", __func__);
			aeon_free_block_node(blknode);
			return;
		}
		if (offset == 0)
			free_list->first_node = blknode;
		free_list->last_node = blknode;

		free_list->num_blocknode++;
	}

}

static void aeon_rebuild_blockmap(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map;
	struct aeon_region_table *art;
	u64 head_addr = AEON_HEAD(sb) + AEON_SB_SIZE + AEON_INODE_SIZE;
	u64 start_addr;
	__le32 *table_blocknr;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		unsigned long blocknr;
		int num_nodes;

		inode_map = aeon_get_inode_map(sb, i);
		table_blocknr = (__le32 *)(i * 32 + head_addr);
		blocknr = le32_to_cpu(*table_blocknr);
		blocknr <<= AEON_SHIFT;
		inode_map->i_table_addr = (void *)(blocknr + AEON_HEAD(sb));

		art = aeon_get_rtable(sb, i);
		num_nodes = art->range_nodes;
		start_addr = (u64)art + AEON_INODE_SIZE;

		do_aeon_rebuild_blockmap(sb, i, start_addr, num_nodes);
	}
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

	if (!(sbi->s_mount_opt & AEON_MOUNT_FORMAT)) {
		aeon_rebuild_blockmap(sb);
		return;
	}

	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		tree = &(free_list->block_free_tree);
		aeon_init_free_list(sb, free_list, i);

		free_list->num_free_blocks = free_list->block_end -
						free_list->block_start + 1;

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
	}
}

static inline
int aeon_rbtree_compare_rangenode(struct aeon_range_node *curr,
				  unsigned long key, enum node_type type)
{
	if (type == NODE_DIR) {
		if (key < curr->hash)
			return -1;
		if (key > curr->hash)
			return 1;
		return 0;
	}

	if (type == NODE_EXTENT) {
		if (key < curr->offset)
			return -1;
		if (key >= (curr->offset + curr->length))
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

int aeon_insert_range_node(struct rb_root *tree,
			   struct aeon_range_node *new_node, enum node_type type)
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

bool aeon_find_range_node(struct rb_root *tree, unsigned long key,
	enum node_type type, struct aeon_range_node **ret_node)
{
	struct aeon_range_node *curr = NULL;
	struct rb_node *temp;
	int compVal;
	bool found = false;

	temp = tree->rb_node;
	while (temp) {
		curr = container_of(temp, struct aeon_range_node, node);
		compVal = aeon_rbtree_compare_rangenode(curr, key, type);

		if (compVal == -1)
			temp = temp->rb_left;
		else if (compVal == 1)
			temp = temp->rb_right;
		else {
			found = true;
			break;
		}
	}

	*ret_node = curr;
	return found;
}

void aeon_destroy_range_node_tree(struct super_block *sb, struct rb_root *tree)
{
	struct aeon_range_node *curr;
	struct rb_node *temp;

	temp = rb_first(tree);
	while (temp) {
		curr = container_of(temp, struct aeon_range_node, node);
		temp = rb_next(temp);
		rb_erase(&curr->node, tree);
		aeon_free_dir_node(curr);
	}
}

static int aeon_find_free_slot(struct rb_root *tree, unsigned long range_low,
			       unsigned long range_high,
			       struct aeon_range_node **prev,
			       struct aeon_range_node **next)
{
	struct aeon_range_node *ret_node = NULL;
	struct rb_node *temp;
	bool ret = false;

	ret = aeon_find_range_node(tree, range_low, NODE_BLOCK, &ret_node);
	if (ret) {
		aeon_dbg("%s ERROR: %lu - %lu already in free list\n",
			 __func__, range_low, range_high);
		return -EINVAL;
	}

	if (!ret_node)
		*prev = *next = NULL;
	else if (ret_node->range_high < range_low) {
		*prev = ret_node;
		temp = rb_next(&ret_node->node);
		if (temp)
			*next = container_of(temp, struct aeon_range_node, node);
		else
			*next = NULL;
	} else if (ret_node->range_low > range_high) {
		*next = ret_node;
		temp = rb_prev(&ret_node->node);
		if (temp)
			*prev = container_of(temp, struct aeon_range_node, node);
		else
			*prev = NULL;
	} else {
		aeon_dbg("%s ERROR: %lu - %lu overlaps with existing node %lu - %lu\n",
			 __func__, range_low, range_high, ret_node->range_low,
			ret_node->range_high);
		return -EINVAL;
	}

	return 0;
}

int aeon_insert_blocks_into_free_list(struct super_block *sb,
				      unsigned long blocknr,
				      int num, unsigned short btype)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	struct rb_root *tree;
	struct aeon_range_node *prev = NULL;
	struct aeon_range_node *next = NULL;
	struct aeon_range_node *curr_node;
	struct aeon_region_table *art;
	unsigned long block_low;
	unsigned long block_high;
	unsigned long num_blocks = 0;
	int cpu_id;
	int ret;
	bool new_node_used = false;

	if (num <= 0) {
		aeon_err(sb, "less zero blocks can't be freed\n");
		return -EINVAL;
	}

	curr_node = aeon_alloc_block_node(sb);
	if (curr_node == NULL)
		return -ENOMEM;

	cpu_id = blocknr / sbi->per_list_blocks;
	free_list = aeon_get_free_list(sb, cpu_id);
	art = aeon_get_rtable(sb, cpu_id);
	spin_lock(&free_list->s_lock);

	tree = &(free_list->block_free_tree);

	num_blocks = aeon_get_numblocks(btype) * num;
	block_low = blocknr;
	block_high = blocknr + num_blocks - 1;

	if (blocknr < free_list->block_start ||
	    blocknr + num > free_list->block_end + 1) {
		aeon_err(sb, "free blocks %lu to %lu, free list %d, start %lu, end %lu\n",
				blocknr, blocknr + num - 1,
				free_list->index,
				free_list->block_start,
				free_list->block_end);
		ret = -EIO;
		goto out;
	}

	ret = aeon_find_free_slot(tree, block_low, block_high, &prev, &next);
	if (ret) {
		aeon_err(sb, "find free slot fail: %d\n", ret);
		goto out;
	}

	if (prev && next && (block_low == prev->range_high + 1) &&
			(block_high + 1 == next->range_low)) {
		rb_erase(&next->node, tree);
		free_list->num_blocknode--;
		prev->range_high = next->range_high;
		if (free_list->last_node == next)
			free_list->last_node = prev;
		aeon_free_block_node(next);
		goto block_found;
	}
	if (prev && (block_low == prev->range_high + 1)) {
		prev->range_high += num_blocks;
		goto block_found;
	}
	if (next && (block_high + 1 == next->range_low)) {
		next->range_low -= num_blocks;
		goto block_found;
	}

	curr_node->range_low = block_low;
	curr_node->range_high = block_high;
	new_node_used = true;
	ret = aeon_insert_blocktree(tree, curr_node);
	if (ret) {
		new_node_used = false;
		goto out;
	}

	if (!prev)
		free_list->first_node = curr_node;
	if (!next)
		free_list->last_node = curr_node;

	free_list->num_blocknode++;

block_found:
	free_list->num_free_blocks += num_blocks;
	art->num_free_blocks += cpu_to_le64(num_blocks);
	art->alloc_data_count--;
	art->alloc_data_pages -= cpu_to_le64(num_blocks);
	art->freed_data_count++;
	art->freed_data_pages += cpu_to_le64(num_blocks);

out:
	spin_unlock(&free_list->s_lock);
	if (new_node_used == false)
		aeon_free_block_node(curr_node);

	return ret;
}

static int not_enough_blocks(struct free_list *free_list,
			     unsigned long num_blocks)
{
	struct aeon_range_node *first = free_list->first_node;
	struct aeon_range_node *last = free_list->last_node;

	if (free_list->num_free_blocks < num_blocks || !first || !last) {
		aeon_dbgv("%s: num_free_blocks=%ld; num_blocks=%ld; first=0x%p; last=0x%p",
			  __func__, free_list->num_free_blocks, num_blocks,
			  first, last);
		return 1;
	}

	return 0;
}

/* Find out the free list with most free blocks */
#ifdef CONFIG_AEON_FS_NUMA
static struct free_list *aeon_get_candidate_free_list(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	int numa_id = 0;
	int cpu_id = 0;
	int num_free_blocks = 0;
	int i;
	int j;

	for (i = 0; i < sbi->numa_nodes; i++) {
		for (j = 0; j < sbi->cpus/sbi->numa_nodes; j++) {
			free_list = &sbi->nm[i].free_lists[j];
			if (free_list->num_free_blocks > num_free_blocks) {
				numa_id = i;
				cpu_id = j;
				num_free_blocks = free_list->num_free_blocks;
			}
		}
	}

	return &sbi->nm[numa_id].free_lists[cpu_id];
}
#else
static int aeon_get_candidate_free_list(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	int cpuid = 0;
	int num_free_blocks = 0;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		if (free_list->num_free_blocks > num_free_blocks) {
			cpuid = i;
			num_free_blocks = free_list->num_free_blocks;
		}
	}

	return cpuid;
}
#endif

/* Return how many blocks allocated */
static long aeon_alloc_blocks_in_free_list(struct super_block *sb,
					   struct free_list *free_list,
					   unsigned short btype,
					   unsigned long num_blocks,
					   unsigned long *new_blocknr)
{
	struct rb_root *tree;
	struct aeon_range_node *curr;
	struct aeon_range_node *next = NULL;
	struct aeon_range_node *prev = NULL;
	struct rb_node *temp;
	struct rb_node *next_node;
	struct rb_node *prev_node;
	unsigned long curr_blocks;
	bool found = 0;
	unsigned long step = 0;

	if (!free_list->first_node || free_list->num_free_blocks == 0) {
		aeon_err(sb, "%s: Can't alloc. free_list->first_node=0x%p free_list->num_free_blocks = %lu",
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
		aeon_dbg("%s: free list %d has %lu free blocks,"
			 "but allocated %lu blocks?\n",
			 __func__, free_list->index,
			 free_list->num_free_blocks, num_blocks);
		return -ENOSPC;
	}

	if (found)
		free_list->num_free_blocks -= num_blocks;
	else {
		aeon_dbg("%s: Can't alloc.  found = %d", __func__, found);
		return -ENOSPC;
	}

	return num_blocks;

}

static int aeon_new_blocks(struct super_block *sb, unsigned long *blocknr,
	unsigned int num, unsigned short btype, int cpuid)
{
	struct free_list *free_list;
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map;
	struct aeon_region_table *art;
	unsigned long num_blocks = 0;
	unsigned long new_blocknr = 0;
	long ret_blocks = 0;
	int retried = 0;

	num_blocks = num * aeon_get_numblocks(btype);

#ifdef CONFIG_AEON_FS_NUMA
#else
	if (cpuid == ANY_CPU)
		cpuid = aeon_get_cpuid(sb);
#endif

#ifdef CONFIG_AEON_FS_NUMA
	free_list = aeon_get_numa_list(sb);
	cpuid = free_list->index;
#else
retry:
	free_list = aeon_get_free_list(sb, cpuid);
	spin_lock(&free_list->s_lock);
#endif

#ifdef CONFIG_AEON_FS_NUMA
numa_retry:
	spin_lock(&free_list->s_lock);

	if (not_enough_blocks(free_list, num_blocks)) {
		aeon_dbgv("%s: cpu %d, free_blocks %lu, required %lu, blocknode %lu\n",
			  __func__, cpuid, free_list->num_free_blocks,
			  num_blocks, free_list->num_blocknode);

		if (retried >= sbi->numa_nodes) {
			dump_stack();
			goto alloc;
		}

		spin_unlock(&free_list->s_lock);
		free_list = aeon_get_candidate_free_list(sb);
		retried++;
		goto numa_retry;
	}
#else
	if (not_enough_blocks(free_list, num_blocks)) {
		aeon_dbgv("%s: cpu %d, free_blocks %lu, required %lu, blocknode %lu\n",
			  __func__, cpuid, free_list->num_free_blocks,
			  num_blocks, free_list->num_blocknode);

		if (retried >= sbi->cpus-1) {
			dump_stack();
			goto alloc;
		}

		spin_unlock(&free_list->s_lock);
		cpuid = aeon_get_candidate_free_list(sb);
		retried++;
		goto retry;
	}
#endif

alloc:
	inode_map = aeon_get_inode_map(sb, cpuid);
	art = AEON_R_TABLE(inode_map);

	ret_blocks = aeon_alloc_blocks_in_free_list(sb, free_list, btype,
						    num_blocks, &new_blocknr);

	if (ret_blocks > 0) {
		art->alloc_data_count++;
		art->alloc_data_pages += cpu_to_le64(ret_blocks);
		art->num_free_blocks = cpu_to_le64(free_list->num_free_blocks);
		art->b_range_low += cpu_to_le32(ret_blocks);
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
int aeon_new_data_blocks(struct super_block *sb,
	struct aeon_inode_info_header *sih, unsigned long *blocknr,
	unsigned long start_blk, unsigned long num, int cpu)
{
	int allocated;

	allocated = aeon_new_blocks(sb, blocknr, num,
				    sih->i_blk_type, cpu);

	if (allocated < 0) {
		aeon_dbg("FAILED: Inode (prev)sih->ino, start blk"
			 "%lu, alloc %d data blocks from %lu to %lu\n",
			  start_blk, allocated, *blocknr,
			  *blocknr + allocated - 1);
	}

	return allocated;
}

/**
 * aeon_dax_get_blocks - The function tries to lookup the requested blocks.
 * Also it allocates new blcoks if these are needed.
 *
 * return > 0, # of blocks mapped or allocated.
 */
int aeon_dax_get_blocks(struct inode *inode, unsigned long iblock,
			unsigned long max_blocks, u32 *bno, bool *new,
			bool *boundary, int create)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh;
	struct aeon_extent *ae;
	unsigned long new_d_blocknr = 0;
	int allocated;
	int length = 0;
	int err = -ENOSPC;

	if (!pi)
		return -ENOENT;

	ae = aeon_search_extent(sb, sih, iblock);
	if (ae) {
		unsigned long offset;

		offset = le32_to_cpu(ae->ex_offset);
		*bno = le64_to_cpu(ae->ex_block);
		length = le16_to_cpu(ae->ex_length) - (iblock - offset);
		*bno += (iblock - offset);

		return length;
	}

	if (!create) {
		length = 0;
		return length;
	}

	mutex_lock(&sih->truncate_mutex);

	aeh = aeon_get_extent_header(pi);
	if (!pi->i_exblocks) {
		pi->i_new = 0;
		pi->i_exblocks++;
		aeon_init_extent_header(aeh);
	}

	allocated = aeon_new_data_blocks(sb, sih, &new_d_blocknr,
					 iblock, max_blocks, ANY_CPU);
	if (allocated <= 0) {
		aeon_err(sb, "failed to get data blocks\n");
		mutex_unlock(&sih->truncate_mutex);
		return err;
	}

	err = aeon_update_extent(sb, inode, new_d_blocknr, iblock, allocated);
	if (err) {
		aeon_err(sb, "failed to update extent\n");
		mutex_unlock(&sih->truncate_mutex);
		return err;
	}

	*bno = new_d_blocknr;

	clean_bdev_aliases(sb->s_bdev, *bno, allocated);
	err = sb_issue_zeroout(sb, *bno, allocated, GFP_NOFS);
	if (err) {
		aeon_err(sb, "%s: ERROR\n", __func__);
		mutex_unlock(&sih->truncate_mutex);
		return err;
	}

	*new = true;

	mutex_unlock(&sih->truncate_mutex);
	return allocated;
}

static void icache_create(struct aeon_sb_info *sbi,
			      struct inode_map *inode_map)
{
	struct icache *init;

	init = kmalloc(sizeof(struct icache), GFP_KERNEL);
	inode_map->im = init;

	INIT_LIST_HEAD(&inode_map->im->imem_list);
}

static void do_aeon_init_new_inode_block(struct super_block *sb,
					 int cpu_id, u32 ino)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map = aeon_get_inode_map(sb, cpu_id);
	struct free_list *free_list = aeon_get_free_list(sb, cpu_id);
	struct rb_root *tree;
	struct rb_node *temp;
	u64 addr = AEON_HEAD(sb) + AEON_SB_SIZE + AEON_INODE_SIZE;
	__le32 *table_blocknr;
	unsigned long table_addr;
	struct aeon_range_node *node;
	unsigned long blocknr = 0;
	u64 temp_addr;
	int prealloc_blocks = AEON_PAGES_FOR_INODE+1;

	if (!(sbi->s_mount_opt & AEON_MOUNT_FORMAT)) {
		struct aeon_region_table *art;

		//table_blocknr = (__le32 *)(cpu_id * 32 + addr);
		//blocknr = le64_to_cpu(*table_blocknr);
		//inode_map->i_table_addr = (void *)((blocknr << AEON_SHIFT) +
		//	   AEON_HEAD(sb));
		//art = AEON_R_TABLE(inode_map);
		art = aeon_get_rtable(sb, cpu_id);
		free_list->num_free_blocks = le64_to_cpu(art->num_free_blocks);
		icache_create(sbi, inode_map);
		return;
	}

	spin_lock(&free_list->s_lock);

	tree = &(free_list->block_free_tree);
	temp = &(free_list->first_node->node);
	node = container_of(temp, struct aeon_range_node, node);

	blocknr = node->range_low;
	temp_addr = (blocknr << AEON_SHIFT) + AEON_HEAD(sb);
	memset((void *)temp_addr, 0, 4096 * prealloc_blocks);
	node->range_low += prealloc_blocks;

	free_list->num_free_blocks -= prealloc_blocks;

	table_blocknr = (__le32 *)(cpu_id * 32 + addr);
	*table_blocknr = cpu_to_le32(blocknr);
	table_addr = blocknr << AEON_SHIFT;
	inode_map->i_table_addr = (void *)(table_addr + AEON_HEAD(sb));

	spin_unlock(&free_list->s_lock);

	icache_create(sbi, inode_map);
}

static void aeon_register_next_inode_block(struct super_block *sb,
					   struct inode_map *inode_map,
					   struct aeon_region_table *art,
					   unsigned long blocknr)
{
	struct aeon_inode *pi;
	unsigned long prev_blocknr = le64_to_cpu(art->i_blocknr);

	pi = (struct aeon_inode *)(AEON_HEAD(sb) + (prev_blocknr<<AEON_SHIFT));

	pi->i_next_inode_block = cpu_to_le64(blocknr);
	art->i_blocknr = cpu_to_le64(blocknr);
}

void aeon_init_new_inode_block(struct super_block *sb, u32 ino)
{
	int i;

	for (i = 0; i < AEON_SB(sb)->cpus; i++)
		do_aeon_init_new_inode_block(sb, i, ino + i);
}

u64 aeon_get_new_inode_block(struct super_block *sb, int cpuid, u32 ino)
{
	struct inode_map *inode_map = aeon_get_inode_map(sb, cpuid);
	struct aeon_region_table *art = AEON_R_TABLE(inode_map);
	unsigned long allocated;
	unsigned long blocknr = 0;
	int num_blocks = AEON_PAGES_FOR_INODE;
	u64 addr;

	if (le16_to_cpu(art->i_allocated) == AEON_I_NUM_PER_PAGE+1) {
		allocated = aeon_new_blocks(sb, &blocknr, num_blocks, 0, cpuid);
		if (allocated != AEON_PAGES_FOR_INODE)
			goto out;
		addr = AEON_HEAD(sb) + (blocknr<<AEON_SHIFT);
		memset((void *)addr, 0, 4096 * allocated);
		aeon_register_next_inode_block(sb, inode_map, art, blocknr);
		art->i_num_allocated_pages += cpu_to_le32(allocated);
		art->i_allocated = cpu_to_le16(1);
		art->i_head_ino = cpu_to_le32(ino);
	} else
		blocknr = le64_to_cpu(art->i_blocknr);

	return blocknr;

out:
	aeon_err(sb, "can't alloc region for inode\n");
	return 0;
}

unsigned long aeon_get_new_dentry_block(struct super_block *sb, u64 *de_addr)
{
	unsigned long allocated;
	unsigned long blocknr = 0;
	int num_blocks = AEON_PAGES_FOR_DENTRY;

	allocated = aeon_new_blocks(sb, &blocknr, num_blocks, 0, ANY_CPU);
	*de_addr = AEON_HEAD(sb) + (blocknr << AEON_SHIFT);
	memset((void *)(*de_addr), 0, allocated * 4096);

	return blocknr;
}

unsigned long aeon_get_new_symlink_block(struct super_block *sb, u64 *pi_addr)
{
	unsigned long allocated;
	unsigned long blocknr = 0;
	int num_blocks = 1;

	allocated = aeon_new_blocks(sb, &blocknr, num_blocks, 0, ANY_CPU);
	*pi_addr = AEON_HEAD(sb) + (blocknr << AEON_SHIFT);

	return blocknr;
}

unsigned long aeon_get_new_extents_block(struct super_block *sb)
{
	unsigned long allocated;
	unsigned long blocknr = 0;
	int num_blocks = 1;

	allocated = aeon_new_blocks(sb, &blocknr, num_blocks, 0, ANY_CPU);
	if (allocated <= 0) {
		aeon_err(sb, "failed to get new exttens block\n");
		return -ENOSPC;
	}

	return blocknr;
}

u64 aeon_get_new_extents_block_addr(struct super_block *sb)
{
	unsigned long allocated;
	unsigned long blocknr = 0;
	int num_blocks = 1;

	allocated = aeon_new_blocks(sb, &blocknr, num_blocks, 0, ANY_CPU);
	if (allocated <= 0) {
		aeon_err(sb, "failed to get new exttens block\n");
		return 0;
	}

	return (blocknr << AEON_SHIFT);
}

u64 aeon_get_new_blk(struct super_block *sb, int cpu_id)
{
	struct free_list *free_list;
	unsigned long blocknr;

	free_list = aeon_get_free_list(sb, cpu_id);
	if (cpu_id == 0)
		blocknr = free_list->block_start + 1;
	else
		blocknr = free_list->block_start;

	free_list->block_start++;

	return (blocknr << AEON_SHIFT);
}

/**
 * aeon_get_xattr_blk - Get a block for extended attribution
 *
 * Return:
 * The head address of the gotten block
 */
u64 aeon_get_xattr_blk(struct super_block *sb)
{
	unsigned long allocated;
	unsigned long blocknr = 0;
	int num_blocks = 1;
	u64 addr;

	allocated = aeon_new_blocks(sb, &blocknr, num_blocks, 0, ANY_CPU);
	if (allocated <= 0) {
		aeon_err(sb, "failed to get new exttens block\n");
		return -ENOSPC;
	}

	addr = blocknr << AEON_SHIFT;
	memset((void *)(AEON_HEAD(sb) + addr), 0, 1<<AEON_SHIFT);

	return addr;
}

u64 aeon_get_new_extents_header_block(struct super_block *sb,
				      struct aeon_extent_header *prev)
{
	struct aeon_extent_header *aeh;
	unsigned long num_blocks = 2;
	unsigned long allocated;
	unsigned long blocknr = 0;
	u64 header_addr;
	u64 extent_addr;

	allocated = aeon_new_blocks(sb, &blocknr, num_blocks, 0, ANY_CPU);
	if (allocated != 2) {
		aeon_err(sb, "failed to get new exttens block\n");
		return -ENOSPC;
	}

	header_addr = (blocknr<<AEON_SHIFT);
	extent_addr = (blocknr+1)<<AEON_SHIFT;
	aeh = (struct aeon_extent_header *)(header_addr + AEON_HEAD(sb));
	memset((void *)aeh, 0, 4096);
	aeh->eh_entries = 0;
	//aeh->eh_depth = 0;
	aeh->eh_blocks = 0;
	//aeh->eh_extent_blocks[0] = extent_addr>>AEON_SHIFT;

	//prev->eh_extent_blocks[PI_MAX_EXTERNAL_EXTENT-1] = header_addr>>AEON_SHIFT;

	return header_addr;
}
