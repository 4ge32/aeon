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

	aeon_dbg("%s: blocknr - %lu ino - %llu\n", __func__, blocknr, le64_to_cpu(pi->aeon_ino));
	de_map = (struct aeon_dentry_map *)((u64)sbi->virt_addr + (blocknr << AEON_SHIFT));
	aeon_dbg("%s: blocknr - %llu\n", __func__, le64_to_cpu(de_map->block_dentry[0]));

	num_entry = le64_to_cpu(de_map->num_dentries);
	if (num_entry == 2)
		return 0;

	global = 0;
	internal = 2;
	de_info = kzalloc(sizeof(struct aeon_dentry_info), GFP_KERNEL);
	adi = kzalloc(sizeof(struct aeon_dentry_invalid), GFP_KERNEL);
	de_info->di = adi;
	INIT_LIST_HEAD(&de_info->di->invalid_list);
	sih->de_info = de_info;
	while (num_entry > 2) {
		if (internal == 8) {
			global++;
			internal = 0;
		}

		d_blocknr = le64_to_cpu(de_map->block_dentry[global]);
		aeon_remove_used_block(sb, d_blocknr);
		d = (struct aeon_dentry *)(sbi->virt_addr +
					  (d_blocknr << AEON_SHIFT) +
					  (internal << AEON_D_SHIFT));

		if (!d->valid) {
			adi->global = le32_to_cpu(d->global_offset);
			adi->internal = le32_to_cpu(d->internal_offset);
			list_add(&adi->invalid_list, &de_info->di->invalid_list);
			aeon_dbg("%s: %u - %lu\n", __func__, adi->internal, adi->global);
			continue;
		}

		aeon_dbg("%s: %s\n", __func__, d->name);
		aeon_insert_dir_tree(sb, sih, d->name, d->name_len, d);

		internal++;
		num_entry--;
	}


	return 0;
}
