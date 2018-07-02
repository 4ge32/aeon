#include <linux/fs.h>

#include "aeon.h"


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
	u64 pi_addr = 0;
	int err;

	aeon_dbg("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	aeon_dbg("%s: %s %d\n", __func__, name, namelen);

	if (namelen == 0)
		return -EINVAL;

	pidir = aeon_get_inode(sb, dir);

	direntry = (struct aeon_dentry *)aeon_get_dentry_block(sb, &pi_addr, ANY_CPU);
	strncpy(direntry->name, name, namelen);
	direntry->name_len = namelen;
	direntry->ino = ino;

	err = aeon_insert_dir_tree(sb, sih, name, namelen, direntry);
	if (err)
		return -ENOMEM;

	dir->i_mtime = dir->i_ctime = current_time(dir);

	return 0;
}

int aeon_remove_dentry(struct dentry *dentry, int dec_link, struct aeon_inode *update)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct qstr *entry = &dentry->d_name;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pidir;
	int ret;

	if (!dentry->d_name.len)
		return -EINVAL;

	ret = aeon_remove_dir_tree(sb, sih, entry->name, entry->len);
	if (ret)
		goto out;

	pidir = aeon_get_inode(sb, dir);

	dir->i_mtime = dir->i_ctime = current_time(dir);

	return 0;
out:
	return ret;
}

static int aeon_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct aeon_range_node *curr = NULL;
	struct rb_node *temp = NULL;
	struct aeon_inode *child_pi;
	struct aeon_dentry *entry;
	unsigned long pos = ctx->pos;
	ino_t ino;
	u64 pi_addr = 0;
	int ret;
	int found = 0;


	if (pos == 0) {
		temp = rb_first(&sih->rb_tree);
	}
	else if (pos == READDIR_END) {
		return 0;
	} else {
		found = aeon_find_range_node(&sih->rb_tree, pos, NODE_DIR, &curr);
		if (found == 1 && pos == curr->hash) {
			aeon_dbg("%s: REACH HERE?\n", __func__);
			temp = &curr->node;
		}
		aeon_dbg("%s: first else statement\n", __func__);
	}

	while (temp) {
		aeon_dbg("%s: NOW\n", __func__);
		curr = container_of(temp, struct aeon_range_node, node);
		entry = curr->direntry;

		pos = BKDRHash(entry->name, entry->name_len);
		ctx->pos = pos;
		ino = __le64_to_cpu(entry->ino);
		if (ino == 0)
			continue;

		ret = aeon_get_inode_address(sih, ino, &pi_addr);

		if (ret) {
			aeon_dbg("%s: get child inode %lu address failed %d\n",
					__func__, ino, ret);
			ctx->pos = READDIR_END;
			return ret;
		}

		child_pi = aeon_get_block(sb, pi_addr);
		aeon_dbg("ctx: ino %llu, name %s, name_len %u\n", (u64)ino, entry->name, entry->name_len);
		if (!dir_emit(ctx, entry->name, entry->name_len, ino, 0755)) {
			aeon_dbg("Here: pos %llu\n", ctx->pos);
			return 0;
		}
		temp = rb_next(temp);
	}

	ctx->pos = READDIR_END;

	return 0;
}

const struct file_operations aeon_dir_operations = {
	.iterate = aeon_readdir,
};
