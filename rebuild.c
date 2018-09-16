#include <linux/fs.h>
#include <linux/slab.h>

#include "aeon.h"


static void aeon_remove_used_block(struct super_block *sb, unsigned long blocknr)
{
	struct free_list *free_list;
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct rb_root *tree;
	struct rb_node *temp;
	struct aeon_range_node *curr;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = aeon_get_free_list(sb, i);
		if (free_list->block_start != blocknr)
			continue;
		tree = &(free_list->block_free_tree);
		temp = &(free_list->first_node->node);

		while (temp) {
			curr = container_of(temp, struct aeon_range_node, node);
			if (curr->range_low == blocknr) {
				curr->range_low++;
				return;
			}
			temp = rb_next(temp);
		}
	}
}

int aeon_rebuild_dir_inode_tree(struct super_block *sb, struct aeon_inode *pi,
				u64 pi_addr, struct aeon_inode_info_header *sih)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_dentry_info *de_info;
	struct aeon_dentry_invalid *adi;
	unsigned long blocknr = le64_to_cpu(pi->dentry_map_block);
	struct aeon_dentry_map *de_map;
	struct aeon_dentry *d;
	int num_entry;
	int global;
	int internal;
	unsigned long d_blocknr;

	de_map = (struct aeon_dentry_map *)((u64)sbi->virt_addr +
					    (blocknr << AEON_SHIFT));

	num_entry = le64_to_cpu(de_map->num_dentries);
	if (num_entry == 2)
		return 0;

	global = 0;
	internal = 2;
	de_info = kzalloc(sizeof(struct aeon_dentry_info), GFP_KERNEL);
	adi = kzalloc(sizeof(struct aeon_dentry_invalid), GFP_KERNEL);
	de_info->di = adi;
	de_info->de_map = de_map;

	mutex_lock(&de_info->dentry_mutex);

	INIT_LIST_HEAD(&de_info->di->invalid_list);
	sih->de_info = de_info;

	while (num_entry > 2) {
		if (internal == AEON_INTERNAL_ENTRY) {
			global++;
			internal = 0;
		}

		d_blocknr = le64_to_cpu(de_map->block_dentry[global]);
		aeon_remove_used_block(sb, d_blocknr);
		d = (struct aeon_dentry *)(sbi->virt_addr +
					   (d_blocknr << AEON_SHIFT) +
					   (internal << AEON_D_SHIFT));

		if (!d->valid) {
			adi = kmalloc(sizeof(struct aeon_dentry_invalid),
				      GFP_KERNEL);
			if (!adi)
				return -ENOMEM;
			adi->global = le32_to_cpu(d->global_offset);
			adi->internal = le32_to_cpu(d->internal_offset);
			list_add(&adi->invalid_list, &de_info->di->invalid_list);
			goto next;
		}

		aeon_insert_dir_tree(sb, sih, d->name, d->name_len, d);
		num_entry--;
next:
		internal++;
	}

	mutex_unlock(&de_info->dentry_mutex);

	return 0;
}

static void imem_cache_rebuild(struct aeon_sb_info *sbi,
			       struct inode_map *inode_map,
			       unsigned long blocknr, u32 start_ino,
			       unsigned allocated, unsigned long *next_blocknr,
			       int space, int cpu_id)
{
	struct aeon_inode *pi;
	struct imem_cache *im;
	struct imem_cache *init;
	struct i_valid_list *ivl;
	struct i_valid_list *ivl_init;
	struct aeon_region_table *art;
	u64 virt_addr = (u64)sbi->virt_addr + (blocknr << AEON_SHIFT);
	u32 ino = start_ino;
	u32 ino_off = sbi->cpus;
	int i;

	/* TODO:
	 * Pruning
	 */
	if (!inode_map->im) {
		init = kmalloc(sizeof(struct imem_cache), GFP_KERNEL);
		inode_map->im = init;
		INIT_LIST_HEAD(&inode_map->im->imem_list);
	}

	if (!inode_map->ivl) {
		ivl_init = kmalloc(sizeof(struct i_valid_list), GFP_KERNEL);
		inode_map->ivl = ivl_init;
		INIT_LIST_HEAD(&inode_map->ivl->i_valid_list);
	}

	art = AEON_R_TABLE(inode_map);

	for (i = space; i < AEON_I_NUM_PER_PAGE; i++) {
		u64 addr;

		addr = virt_addr + (i << AEON_I_SHIFT);
		pi = (struct aeon_inode *)addr;
		if (space == i) {
			*next_blocknr = le64_to_cpu(pi->i_next_inode_block);
			inode_map->curr_i_blocknr = *next_blocknr;
		}
		if (pi->valid) {
			/* Recovering created object */
			ivl = kmalloc(sizeof(struct i_valid_list), GFP_KERNEL);
			ivl->ino = ino;
			ivl->addr = addr;
			list_add_tail(&ivl->i_valid_list, &inode_map->ivl->i_valid_list);
		} else {
			/* Recovering space that had benn used */
			u32 i = le32_to_cpu(art->i_range_high);
			if (ino > (i * sbi->cpus + cpu_id))
				goto next;
			im = kmalloc(sizeof(struct imem_cache), GFP_KERNEL);
			im->ino = ino;
			im->addr = addr;
			im->head = im;
			im->independent = 1;
			list_add_tail(&im->imem_list, &inode_map->im->imem_list);
		}
next:
		ino += ino_off;
	}
}

void aeon_rebuild_inode_cache(struct super_block *sb, int cpu_id)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map = &sbi->inode_maps[cpu_id];
	struct aeon_region_table *art;
	struct free_list *free_list;
	unsigned long offset;
	unsigned long blocknr = 0;
	int ino = AEON_INODE_START + cpu_id;
	int i;

	if (sbi->s_mount_opt & AEON_MOUNT_FORMAT)
		return;

	mutex_lock(&inode_map->inode_table_mutex);

	free_list = aeon_get_free_list(sb, cpu_id);

	if (cpu_id == 0)
		offset = 1;
	else
		offset = free_list->block_start;
	inode_map->i_table_addr = (void *)((u64)sbi->virt_addr +
					   (offset << AEON_SHIFT));

	art = AEON_R_TABLE(inode_map);

	/* the first page for inode contains inode_table
	 * so it leaves space of a inode size between head
	 * of page and firtst inode (last argument).
	 */
	imem_cache_rebuild(sbi, inode_map, offset, ino,
			   le64_to_cpu(art->allocated), &blocknr, 1, cpu_id);
	offset = blocknr;
	ino = ino + (AEON_I_NUM_PER_PAGE - 1) * 2;

	for (i = 1; i < le32_to_cpu(art->i_num_allocated_pages); i++) {
		imem_cache_rebuild(sbi, inode_map, offset, ino,
				   le64_to_cpu(art->allocated), &blocknr, 0, cpu_id);
		offset = blocknr;
		ino = ino + (AEON_I_NUM_PER_PAGE) * 2;
	}

	mutex_unlock(&inode_map->inode_table_mutex);
	//aeon_dbgv("%s: %u\n", __func__, le32_to_cpu(art->i_num_allocated_pages));
	//aeon_dbgv("%s: %llu\n", __func__, le64_to_cpu(art->allocated));
}
