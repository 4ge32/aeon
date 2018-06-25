#include <linux/fs.h>

#include "aeon.h"
#include "super.h"
#include "inode.h"
#include "balloc.h"

int aeon_insert_dir_tree(struct super_block *sb, struct aeon_inode_info_header *sih,
			 const char *name, int namelen, struct aeon_dentry *direntry)
{
	struct aeon_range_node *node = NULL;
	unsigned long hash;
	int ret;

	hash = BKDRHash(name, namelen);

	node = aeon_alloc_dir_node(sb);
	if (!node)
		return -ENOMEM;

	node->hash = hash;
	node->direntry = direntry;
	ret = aeon_insert_range_node(&sih->rb_tree, node, NODE_DIR);
	if (ret) {
		aeon_free_dir_node(node);
		aeon_err(sb, "%s ERROR %d: %s\n", __func__, ret, name);
	}

	return ret;
}

int aeon_add_dentry(struct dentry *dentry, u64 ino, int inc_link)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pidir;
	struct aeon_dentry *direntry;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	int err;

	aeon_dbg("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	aeon_dbg("%s: %s %d\n", __func__, name, namelen);

	if (namelen == 0)
		return -EINVAL;

	pidir = aeon_get_inode(sb, dir);

	direntry = (struct aeon_dentry *)aeon_get_block(sb, 4096*3);
	strncpy(direntry->name, name, namelen);
	direntry->name_len = namelen;
	direntry->ino = ino;

	err = aeon_insert_dir_tree(sb, sih, name, namelen, direntry);
	if (err)
		return -ENOMEM;

	dir->i_mtime = dir->i_ctime = current_time(dir);

	return 0;
}
