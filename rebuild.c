#include <linux/fs.h>

#include "aeon.h"


int aeon_rebuild_dir_inode_tree(struct super_block *sb, struct aeon_inode *pi,
			       u64 pi_addr, struct aeon_inode_info_header *sih)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long blocknr = le64_to_cpu(pi->i_dentry);
	struct aeon_dentry_map *de;
	struct aeon_dentry *d;
	int num_entry;
	int i;

	aeon_dbg("%s: blocknr - %lu ino - %llu\n", __func__, blocknr, le64_to_cpu(pi->aeon_ino));
	de = (struct aeon_dentry_map *)((u64)sbi->virt_addr + blocknr * AEON_DEF_BLOCK_SIZE_4K);


	num_entry = le64_to_cpu(de->num_dentries);
	for (i = 0; i < num_entry; i++) {
		d = (struct aeon_dentry *)(sbi->virt_addr + de->block_dentry[i] * AEON_DEF_BLOCK_SIZE_4K);
		aeon_dbg("%s: %s\n", __func__, d->name);
		aeon_insert_dir_tree(sb, sih, d->name, d->name_len, d);
	}


	return 0;

}
