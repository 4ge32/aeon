#include <linux/fs.h>
#include <linux/slab.h>

#include "aeon.h"


int aeon_alloc_block_free_lists(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct free_list *free_list;
	int i;

	sbi->free_lists = kcalloc(sbi->cpus,
				  sizeof(struct free_list), GFP_KERNEL);
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

static int not_enough_blocks(struct free_list *free_list,
			     unsigned long num_blocks)
{
	struct aeon_range_node *first = free_list->first_node;
	struct aeon_range_node *last = free_list->last_node;

	if (free_list->num_free_blocks < num_blocks || !first || !last) {
		aeon_dbg("%s: num_free_blocks=%ld; num_blocks=%ld; first=0x%p; last=0x%p",
			 __func__, free_list->num_free_blocks, num_blocks,
			 first, last);
		return 1;
	}

	return 0;
}

/* Return how many blocks allocated */
static long aeon_alloc_blocks_in_free_list(struct super_block *sb,
					   struct free_list *free_list,
					   unsigned short btype,
					   unsigned long num_blocks,
					   unsigned long *new_blocknr)
{
	struct rb_root *tree;
	struct aeon_range_node *curr, *next = NULL, *prev = NULL;
	struct rb_node *temp, *next_node, *prev_node;
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
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map;
	struct aeon_region_table *art;
	unsigned long num_blocks = 0;
	unsigned long new_blocknr = 0;
	long ret_blocks = 0;
	int retried = 0;

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
	ret_blocks = aeon_alloc_blocks_in_free_list(sb, free_list, btype,
						    num_blocks, &new_blocknr);

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
	inode_map = &sbi->inode_maps[cpuid];
	art = AEON_R_TABLE(inode_map);
	art->b_range_low += cpu_to_le32(ret_blocks);

	//aeon_dbgv("%s block number - %lu\n", __func__, *blocknr);

	return ret_blocks / aeon_get_numblocks(btype);
}

// Allocate data blocks.  The offset for the allocated block comes back in
// blocknr.  Return the number of blocks allocated.
static int aeon_new_data_blocks(struct super_block *sb,
	struct aeon_inode_info_header *sih, unsigned long *blocknr,
	unsigned long start_blk, unsigned int num, int cpu)
{
	int allocated;

	allocated = aeon_new_blocks(sb, blocknr, num,
				    sih->i_blk_type, cpu);

	if (allocated < 0) {
		aeon_dbg("FAILED: Inode (prev)sih->ino, start blk %lu, alloc %d data blocks from %lu to %lu\n",
			  start_blk, allocated, *blocknr,
			  *blocknr + allocated - 1);
	} else {
		//aeon_dbg("Inode %lu, start blk %lu, alloc %d data blocks from %lu to %lu\n",
		//	  sih->ino, start_blk, allocated, *blocknr,
		//	  *blocknr + allocated - 1);
	}
	return allocated;
}

static int aeon_find_data_blocks(struct super_block *sb,
				 struct aeon_inode *pi,
				 unsigned long *bno, int *num_blocks)
{
	struct aeon_extent_header *aeh = AEON_EXTENT_HEADER(sb, pi);
	struct aeon_extent *ae = AEON_EXTENT(sb, pi);

	if (pi->i_block == 0)
		return 0;

	if (aeh->eh_entries == 0)
		return 0;

	*bno = ae->ex_block;
	*num_blocks = ae->ex_length;

	return 1;
}

static u32 seach_extent(struct super_block *sb,
			struct aeon_inode *pi, unsigned long iblock)
{
	struct aeon_extent_header *aeh;
	struct aeon_extent *ae;
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long block;
	int i;

	aeh = AEON_EXTENT_HEADER(sb, pi);
	ae = AEON_EXTENT(sb, pi);

	//aeon_dbg("%s: %d\n", __func__, le16_to_cpu(aeh->eh_entries));
	if (le16_to_cpu(aeh->eh_entries) <= iblock)
		return 0;

	//aeon_dbg("%s: %lu\n", __func__, iblock);
	for (i = 0; i < iblock; i++) {
		block = le64_to_cpu(ae->next_block);
		//aeon_dbgv("%s: 0x%lx\n", __func__, block);
		ae = (struct aeon_extent *)((block << 12) + sbi->virt_addr);
	}

	return le64_to_cpu(ae->ex_block);
}

/*
 * return > 0, # of blocks mapped or allocated.
 * return = 0, if plain lookup failed.
 * return < 0, error case.
 */
int aeon_dax_get_blocks(struct inode *inode, unsigned long iblock,
			unsigned long max_blocks, u32 *bno, bool *new,
			bool *boundary, int create)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pi;
	struct aeon_extent_header *aeh;
	struct aeon_extent *ae;
	struct aeon_extent *new_ae;
	unsigned long blocknr = 0;
	int num_blocks = 1;
	int allocated;
	int found;

	/* TODO:
	 * Allocating regions should be alignment
	 *
	 */

	pi = aeon_get_inode(sb, sih);
	//inode->i_ctime = inode->i_mtime = current_time(inode);

	found = aeon_find_data_blocks(sb, pi, &blocknr, &num_blocks);
	if (found) {
		//*bno = blocknr;
		//if (iblock == 0) {
		//	aeon_dbg("%s: retunr num_blocks\n", __func__);
		//	return num_blocks;
		//}
		*bno = seach_extent(sb, pi, iblock);
		if (*bno == 0)
			goto create;
		else
			return num_blocks;
	}

	if (create == 0) {
		/* return page offset */
		//aeon_dbg("%s: create == 0\n", __func__);
		*bno = seach_extent(sb, pi, iblock);
		return num_blocks;
	}

create:
	/* Return initialized blocks to the user */
	if (pi->i_block == 0) {
		/* TODO:
		 * Maybe cpuid can be specified by inode information.
		 * Try to allocate continuous region.
		 */
		allocated = aeon_new_blocks(sb, &blocknr, 1, 0, ANY_CPU);
		pi->i_block = blocknr;
		aeh = AEON_EXTENT_HEADER(sb, pi);
		aeh->eh_entries = 0;
		aeh->eh_max = 4;
		aeh->eh_depth = 0;
		aeh->eh_curr_block = 0;
		aeh->eh_iblock = 0;

		blocknr = 0;
	} else
		aeh = AEON_EXTENT_HEADER(sb, pi);

	if (le32_to_cpu(aeh->eh_iblock) == iblock && iblock != 0)
		return num_blocks;

	allocated = aeon_new_blocks(sb, &blocknr, 1, 0, ANY_CPU);
	//aeon_dbg("%s: allocated - %d, blocknr - %lu, num_blocks - %d\n", __func__, allocated, blocknr, num_blocks);
	if (pi->i_blocks == 0) {
		pi->i_blocks = blocknr;
		ae = AEON_EXTENT(sb, pi);
		ae->next_block = 0;

		allocated = aeon_new_data_blocks(sb, sih, &blocknr, iblock, num_blocks, ANY_CPU);
		//aeon_dbg("%s: allocated - %d, blocknr - %lu, num_blocks - %d\n", __func__, allocated, blocknr, num_blocks);
		ae->ex_length = allocated;
		ae->ex_block = blocknr;

		aeh->eh_curr_block = blocknr;
		aeh->eh_iblock = cpu_to_le32(iblock);
	} else {
		new_ae = (struct aeon_extent *)((blocknr << 12) + sbi->virt_addr);
		ae = AEON_EXTENT(sb, pi);
		//walk_extent(ae);
		while (ae->next_block != 0) {
			ae = (struct aeon_extent *)((le64_to_cpu(ae->next_block << 12)) + sbi->virt_addr);
		}
		ae->next_block = blocknr;

		allocated = aeon_new_data_blocks(sb, sih, &blocknr, iblock, num_blocks, ANY_CPU);
		//aeon_dbg("%s: allocated - %d, blocknr - %lu, num_blocks - %d\n", __func__, allocated, blocknr, num_blocks);
		new_ae->ex_length = allocated;
		new_ae->ex_block = blocknr;
		new_ae->next_block = 0;

		aeh->eh_curr_block = blocknr;
		aeh->eh_iblock = cpu_to_le32(iblock);
	}

	*bno = blocknr;
	aeh->eh_entries++;

	return allocated;
}

static void imem_cache_create(struct aeon_sb_info *sbi,
			      struct inode_map *inode_map,
			      unsigned long blocknr,
			      u64 start_ino, int space)
{
	struct imem_cache *init;
	struct imem_cache *ims;
	struct imem_cache *im;
	u64 virt_addr = (u64)sbi->virt_addr + (blocknr << AEON_SHIFT);
	int ino_off = sbi->cpus;
	int ino = start_ino;
	int i;

	init = kmalloc(sizeof(struct imem_cache), GFP_KERNEL);
	inode_map->im = init;

	INIT_LIST_HEAD(&inode_map->im->imem_list);
	ims = kmalloc(AEON_I_NUM_PER_PAGE * sizeof(struct imem_cache), GFP_KERNEL);
	for (i = space; i < AEON_I_NUM_PER_PAGE; i++) {
		im = &ims[i];
		im->ino = ino;
		im->addr = virt_addr + (i << AEON_I_SHIFT);
		im->head = ims;
		im->independent = 0;
		list_add_tail(&im->imem_list, &inode_map->im->imem_list);

		ino += ino_off;
	}
}

u64 search_imem_cache(struct aeon_sb_info *sbi,
		      struct inode_map *inode_map, ino_t ino)
{
	struct imem_cache *im;
	u64 addr;

	list_for_each_entry(im, &inode_map->im->imem_list, imem_list) {
		if (im->ino == ino)
			goto found;
	}

	return 0;

found:
	addr = im->addr;
	list_del(&im->imem_list);
	if (list_empty(&inode_map->im->imem_list) || im->independent == 1)
		kfree(im->head);

	return addr;
}

static void aeon_register_next_inode_block(struct aeon_sb_info *sbi,
					   struct inode_map *inode_map,
					   struct aeon_region_table *art,
					   unsigned long blocknr)
{
	unsigned int offset = le32_to_cpu(art->i_num_allocated_pages);
	struct aeon_inode *pi;

	/* TODO:
	 * it can be integrated.
	 */
	if (offset == 1)
		pi = (struct aeon_inode *)((u64)inode_map->i_table_addr +
					   (1 << AEON_I_SHIFT));
	else
		pi = (struct aeon_inode *)((u64)inode_map->i_block_addr);

	pi->i_next_inode_block = cpu_to_le64(blocknr);
	inode_map->i_block_addr = (void *)((blocknr << AEON_SHIFT) +
					   (u64)sbi->virt_addr);
}

u64 aeon_get_new_inode_block(struct super_block *sb, int cpuid, u32 ino)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map = &sbi->inode_maps[cpuid];
	struct aeon_region_table *art = AEON_R_TABLE(inode_map);
	unsigned long allocated;
	unsigned long blocknr = 0;
	int num_blocks = 1;

	if (!inode_map->im || list_empty(&inode_map->im->imem_list)) {
		allocated = aeon_new_blocks(sb, &blocknr, num_blocks, 0, cpuid);
		if (allocated != 1)
			goto out;
		aeon_register_next_inode_block(sbi, inode_map, art, blocknr);
		art->i_num_allocated_pages++;
		inode_map->virt_addr = (void *)((blocknr << AEON_SHIFT) +
						(u64)sbi->virt_addr);
		inode_map->curr_i_blocknr = blocknr;
		imem_cache_create(sbi, inode_map, blocknr, ino, 0);
	} else
		blocknr = inode_map->curr_i_blocknr;

	return blocknr;

out:
	aeon_err(sb, "can't alloc region for inode\n");
	return 0;
}

void aeon_init_new_inode_block(struct super_block *sb, int cpuid, ino_t ino)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map = &sbi->inode_maps[cpuid];
	struct free_list *free_list = aeon_get_free_list(sb, cpuid);
	unsigned long blocknr = 0;
	u64 addr = (u64)sbi->virt_addr + AEON_SB_SIZE + AEON_INODE_SIZE;
	__le64 *table_blocknr;

	if (!(sbi->s_mount_opt & AEON_MOUNT_FORMAT)) {
		table_blocknr = (__le64 *)(cpuid * 64 + addr);
		blocknr = le64_to_cpu(*table_blocknr);
		inode_map->virt_addr = (void *)((blocknr << AEON_SHIFT) +
						(u64)sbi->virt_addr);
		inode_map->i_table_addr = inode_map->virt_addr;
		return;
	}

	if (!inode_map->im || list_empty(&inode_map->im->imem_list)) {
		struct rb_root *tree;
		struct rb_node *temp;
		struct aeon_range_node *node;
		struct aeon_region_table_blocknrartb;

		spin_lock(&free_list->s_lock);

		tree = &(free_list->block_free_tree);
		temp = &(free_list->first_node->node);
		node = container_of(temp, struct aeon_range_node, node);

		blocknr = node->range_low;
		node->range_low++;

		free_list->num_free_blocks--;
		free_list->alloc_data_count++;
		free_list->alloc_data_pages++;

		table_blocknr = (__le64 *)(cpuid * 64 + addr);
		*table_blocknr = cpu_to_le64(blocknr);

		spin_unlock(&free_list->s_lock);

		inode_map->virt_addr = (void *)((blocknr << AEON_SHIFT) +
						(u64)sbi->virt_addr);
		inode_map->i_table_addr = inode_map->virt_addr;
		inode_map->curr_i_blocknr = blocknr;
		imem_cache_create(sbi, inode_map, blocknr, ino, 1);
		//aeon_dbgv("%s: %lu\n", __func__, blocknr);
	}

}

// Allocate dentry block.  The offset for the allocated block comes back in
// blocknr.  Return the number of blocks allocated (should be 1).
unsigned long aeon_get_new_dentry_block(struct super_block *sb,
					u64 *pi_addr, int cpuid)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long allocated;
	unsigned long blocknr = 0;

	allocated = aeon_new_blocks(sb, &blocknr, 1, 0, ANY_CPU);

	*pi_addr = (u64)sbi->virt_addr + (blocknr << AEON_SHIFT);

	return blocknr;
}

unsigned long aeon_get_new_dentry_map_block(struct super_block *sb,
					    u64 *pi_addr, int cpuid)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long allocated;
	unsigned long blocknr = 0;

	allocated = aeon_new_blocks(sb, &blocknr, 1, 0, ANY_CPU);

	*pi_addr = (u64)sbi->virt_addr + blocknr * AEON_DEF_BLOCK_SIZE_4K;

	return blocknr;
}

unsigned long aeon_get_new_symlink_block(struct super_block *sb,
					 u64 *pi_addr, int cpuid)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long allocated;
	unsigned long blocknr = 0;

	allocated = aeon_new_blocks(sb, &blocknr, 1, 0, ANY_CPU);

	*pi_addr = (u64)sbi->virt_addr + blocknr * AEON_DEF_BLOCK_SIZE_4K;

	return blocknr;
}
