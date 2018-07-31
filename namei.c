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
	aeon_dbg("%s\n", __func__);
	return 0;
}

static int aeon_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pidir;
	struct aeon_inode update_dir;
	int ret = -ENOMEM;

	pidir = aeon_get_inode(sb, sih);

	ret = aeon_remove_dentry(dentry, 0, &update_dir);
	if (ret)
		goto out;

	inode->i_ctime = dir->i_ctime;

	if (inode->i_nlink)
		drop_nlink(inode);

	return 0;
out:
	aeon_err(sb, "%s return %d\n", __func__, ret);
	return ret;
}

static int aeon_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
	aeon_dbg("%s\n", __func__);
	return 0;
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
	struct aeon_inode update_dir;
	int err = ENOTEMPTY;

	if (!inode)
		return -ENOENT;

	pidir = aeon_get_inode(sb, sih);

	if (aeon_inode_by_name(dir, &dentry->d_name) == 0)
		return -ENOENT;

	aeon_dbg("%s: inode %lu, dir %lu, link %d\n", __func__,
					inode->i_ino, dir->i_ino, dir->i_nlink);

	err = aeon_remove_dentry(dentry, -1, &update_dir);
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
	//struct inode *new_inode = d_inode(new_dentry);
	struct super_block *sb = old_dir->i_sb;
	struct aeon_inode_info *o_si = AEON_I(old_dir);
	struct aeon_inode_info_header *o_sih = &o_si->header;
	struct aeon_dentry *old_de;
	struct aeon_dentry *dir_de = NULL;
	struct aeon_inode *pi = aeon_get_inode(sb, o_sih);
	struct qstr *old_entry = &old_dentry->d_name;
	//struct qstr *new_entry = &new_dentry->d_name;
	int err;

	old_de = aeon_find_dentry(sb, pi, old_dir, old_entry->name, old_entry->len);
	if (old_de == NULL) {
		err = -ENOENT;
		goto out;
	}

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
	        //dir_de = aeon_dotdot(old_inode);
		if (!dir_de)
			goto out;
	}

	//strncpy(direntry->name, new_entry->name, new_entry->len);
	//direntry->name_len = new_entry->len;

	return 0;

out:
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
