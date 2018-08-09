#include <linux/fs.h>
#include <linux/pagemap.h>

#include "aeon.h"


static int aeon_create(struct inode *dir, struct dentry *dentry,
			umode_t mode, bool excl)
{
	struct aeon_inode *pidir;
	struct super_block *sb = dir->i_sb;
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct inode *inode = NULL;
	u64 pi_addr = 0;
	u64 ino;
	int err = PTR_ERR(inode);

	pidir = aeon_get_inode(sb, sih);

	ino = aeon_new_aeon_inode(sb, &pi_addr);
	if (ino == 0)
		goto out;

	err = aeon_add_dentry(dentry, ino, 0);
	if (err)
		goto out;

	inode = aeon_new_vfs_inode(TYPE_CREATE, dir, pi_addr, ino, mode, 0, 0, &dentry->d_name);
	if (IS_ERR(inode))
		goto out;

	d_instantiate(dentry, inode);

	aeon_sb->s_num_inodes++;

	return 0;

out:
	aeon_err(sb, "%s return %d\n", __func__, err);
	return err;
}

static struct dentry *aeon_lookup(struct inode *dir, struct dentry *dentry, unsigned int flag)
{
	struct inode *inode = NULL;
	ino_t ino = 0;


	aeon_dbg("%s %s %lu\n", __func__, dentry->d_name.name, ino);

	ino = aeon_inode_by_name(dir, &dentry->d_name);
	aeon_dbg("%s %s %lu\n", __func__, dentry->d_name.name, ino);
	if (ino) {
		inode = aeon_iget(dir->i_sb, ino);
		aeon_dbg("%s: %lu\n", __func__, ino);
		if (inode == ERR_PTR(-ESTALE) || inode == ERR_PTR(-ENOMEM)
				|| inode == ERR_PTR(-EACCES)) {
			aeon_err(dir->i_sb,
				  "%s: get inode failed: %lu\n",
				  __func__, (unsigned long)ino);
			return ERR_PTR(-EIO);
		}
	}

	return d_splice_alias(inode, dentry);
}

static int aeon_link(struct dentry *dest_dentry, struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dest_dentry);
	int err;

	inode->i_ctime = current_time(inode);
	inode_inc_link_count(inode);
	ihold(inode);

	err = aeon_add_dentry(dentry, inode->i_ino, 0);
	if (!err) {
		d_instantiate(dentry, inode);
		return 0;
	}
	inode_dec_link_count(inode);
	iput(inode);

	return err;
}

static int aeon_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pidir;
	struct aeon_inode update_dir;
	struct aeon_dentry *remove_entry;
	int ret = -ENOMEM;


	pidir = aeon_get_inode(sb, sih);

	/* TODO:
	 * store pointer of dentry structure on pmem in d_fsdata for
	 * extracting data fastly. Following if statement assume the
	 * situation. Maybe it can be implemented in lookup method?
	 */
	if (dentry->d_fsdata) {
		struct aeon_dentry_info *di;

		di = (struct aeon_dentry_info *)(dentry->d_fsdata);
		remove_entry = di->de;
	} else {
		struct qstr *name = &dentry->d_name;
		remove_entry = aeon_find_dentry(sb, NULL, dir, name->name, name->len);
	}

	ret = aeon_remove_dentry(dentry, 0, &update_dir, remove_entry);
	if (ret)
		goto out;

	inode->i_ctime = dir->i_ctime;

	if (inode->i_nlink)
		drop_nlink(inode);

	pidir->i_links_count--;

	return 0;
out:
	aeon_err(sb, "%s return %d\n", __func__, ret);
	return ret;
}

static int aeon_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
	struct super_block *sb = dir->i_sb;
	int err = -ENAMETOOLONG;
	unsigned l = strlen(symname) + 1;
	struct inode *inode;
	struct aeon_inode_info *si;
	struct aeon_inode_info_header *sih;
	struct aeon_inode *pi;
	u64 pi_addr = 0;
	u64 ino;

	if (l > sb->s_blocksize)
		goto err;

	ino = aeon_new_aeon_inode(sb, &pi_addr);
	if (ino == 0) {
		err = -ENOSPC;
		goto err;
	}

	err = aeon_add_dentry(dentry, ino, 0);
	if (err)
		goto err;

	inode = aeon_new_vfs_inode(TYPE_SYMLINK, dir, pi_addr, ino,
				   S_IFLNK|0777, l, 0, &dentry->d_name);

	si = AEON_I(inode);
	sih = &si->header;
	pi = aeon_get_inode(sb, sih);
	err = aeon_block_symlink(sb, pi, symname, l);
	if (err)
		goto err;

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	return 0;
err:
	aeon_err(sb, "%s return %d\n", err);
	return err;
}

static int aeon_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode = NULL;
	struct super_block *sb = dir->i_sb;
	u64 ino;
	u64 pi_addr = 0;
	int err = -EMLINK;


	ino = aeon_new_aeon_inode(sb, &pi_addr);
	if (ino == 0)
		goto out;

	err = aeon_add_dentry(dentry, ino, 0);

	inode = aeon_new_vfs_inode(TYPE_MKDIR, dir, pi_addr, ino,
				   S_IFDIR | mode, sb->s_blocksize,
				   0, &dentry->d_name);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	d_instantiate(dentry, inode);

	return 0;
out:
	aeon_err(sb, "%s return %d\n", __func__, err);
	return err;
}

static int aeon_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pidir;
	struct aeon_inode_info *csi = AEON_I(inode);
	struct aeon_inode_info_header *csih = &csi->header;
	struct aeon_inode *pi;
	struct aeon_inode update_dir;
	struct aeon_dentry *remove_entry;
	int err = ENOTEMPTY;


	pidir = aeon_get_inode(sb, sih);
	pi = aeon_get_inode(sb, csih);

	if (dentry->d_fsdata) {
		/* TODO:
		 * This block has meaning?
		 */
		struct aeon_dentry_info *di;

		di = (struct aeon_dentry_info *)(dentry->d_fsdata);
		remove_entry = di->de;
	} else {
		struct qstr *name = &dentry->d_name;

		if (!aeon_empty_dir(inode))
			return -ENOTEMPTY;
		remove_entry = aeon_find_dentry(sb, NULL, dir, name->name, name->len);
	}

	err = aeon_remove_dentry(dentry, -1, &update_dir, remove_entry);
	if (err)
		goto end_rmdir;

	clear_nlink(inode);
	inode->i_ctime = dir->i_ctime;

	if (dir->i_nlink)
		drop_nlink(dir);

	return 0;

end_rmdir:
	aeon_err(sb, "%s return %d\n", __func__, err);
	return err;
}

static int aeon_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry,
		       unsigned int flags)
{
	struct inode *old_inode = d_inode(old_dentry);
	struct inode *new_inode = d_inode(new_dentry);
	struct super_block *sb = old_dir->i_sb;
	struct aeon_inode_info *o_si = AEON_I(old_inode);
	struct aeon_inode_info_header *o_sih = &o_si->header;
	struct aeon_dentry *old_de;
	struct aeon_dentry *dir_de = NULL;
	struct aeon_dentry *new_de;
	struct aeon_inode *pi = aeon_get_inode(sb, o_sih);
	struct qstr *old_name = &old_dentry->d_name;
	struct qstr *new_name = &new_dentry->d_name;
	int err;

	aeon_dbg("SEE IT !!! - %s\n", old_name->name);

	old_de = aeon_find_dentry(sb, pi, old_dir, old_name->name, old_name->len);
	if (old_de == NULL) {
		err = -ENOENT;
		goto out_dir;
	}

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
	        dir_de = aeon_dotdot(sb, o_sih);
		if (!dir_de)
			goto out_dir;
	}

	if (new_inode) {
		aeon_dbg("1: HELLO\n");
		err = -ENOTEMPTY;
		if (dir_de && !aeon_empty_dir(new_inode))
			goto out_dir;

		err = -ENOENT;
		new_de = aeon_find_dentry(sb, NULL, new_dir, new_name->name, new_name->len);
		if (!new_de)
			goto out_dir;
		aeon_set_link(new_dir, new_de, old_inode, 1);
		new_inode->i_ctime = current_time(new_inode);
		if (dir_de)
			drop_nlink(new_inode);
		inode_dec_link_count(new_inode);
	} else {
		err = aeon_add_dentry(new_dentry, old_inode->i_ino, 0);
		if (err)
			goto out_dir;
		if (dir_de)
			inode_inc_link_count(new_dir);
	}

	old_inode->i_ctime = current_time(old_inode);
	mark_inode_dirty(old_inode);

	aeon_remove_dentry(old_dentry, 0, pi, old_de);
	old_de->invalid = 0;

	if (dir_de) {
		aeon_dbg("2: HELLO\n");
		if (old_dir != new_dir)
			aeon_set_link(old_inode, dir_de, new_dir, 0);
		inode_dec_link_count(old_dir);
	}

	return 0;

out_dir:
	aeon_err(sb, "%s return %d\n", __func__, err);
	return err;
}

static int aeon_mknod (struct inode * dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
	aeon_dbg("%s\n", __func__);
	return 0;
}

const struct inode_operations aeon_dir_inode_operations = {
	.create  = aeon_create,
	.lookup  = aeon_lookup,
	.link    = aeon_link,
	.unlink  = aeon_unlink,
	.symlink = aeon_symlink,
	.mkdir   = aeon_mkdir,
	.rmdir   = aeon_rmdir,
	.rename  = aeon_rename,
	.mknod   = aeon_mknod,
};
