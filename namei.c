#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/slab.h>

#include "aeon.h"


static int aeon_create(struct inode *dir, struct dentry *dentry,
		       umode_t mode, bool excl)
{
	struct super_block *sb = dir->i_sb;
	struct aeon_inode *pidir;
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);
	struct inode *inode = NULL;
	u64 pi_addr = 0;
	u64 i_blocknr = 0;
	u64 d_blocknr = 0;
	u32 ino;
	int err = PTR_ERR(inode);

	pidir = aeon_get_inode(sb, &AEON_I(dir)->header);
	if (!pidir)
		goto out;

	ino = aeon_new_aeon_inode(sb, &pi_addr, &i_blocknr);
	if (ino == 0)
		goto out;

	err = aeon_add_dentry(dentry, ino, i_blocknr, &d_blocknr, 0);
	if (err)
		goto out;

	inode = aeon_new_vfs_inode(TYPE_CREATE, dir, pi_addr, ino, mode,
				   le32_to_cpu(pidir->aeon_ino),
				   d_blocknr, 0, 0, &dentry->d_name);
	if (IS_ERR(inode))
		goto out;

	d_instantiate(dentry, inode);

	aeon_sb->s_num_inodes++;
	aeon_update_super_block_csum(aeon_sb);

	return 0;

out:
	aeon_err(sb, "%s return %d\n", __func__, err);
	return err;
}

static struct dentry *aeon_lookup(struct inode *dir,
				  struct dentry *dentry,
				  unsigned int flag)
{
	struct inode *inode = NULL;
	u32 ino = 0;

	ino = aeon_inode_by_name(dir, &dentry->d_name);
	if (ino) {
		//aeon_dbg("%s: %u %s\n", __func__, ino, dentry->d_name.name);
		inode = aeon_iget(dir->i_sb, ino);
		if (inode == ERR_PTR(-ESTALE) || inode == ERR_PTR(-ENOMEM)
		    || inode == ERR_PTR(-EACCES)) {
			aeon_err(dir->i_sb,
				 "%s: get inode failed: %u\n",
				 __func__, ino);
			return ERR_PTR(-EIO);
		}
	}

	return d_splice_alias(inode, dentry);
}

static int aeon_link(struct dentry *dest_dentry,
		     struct inode *dir, struct dentry *dentry)
{
	struct inode *dest_inode = d_inode(dest_dentry);
	struct aeon_inode_info *si = AEON_I(dest_inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pidir;
	struct aeon_inode *pi;
	struct super_block *sb = dir->i_sb;
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);
	struct qstr *name = &dest_dentry->d_name;
	struct aeon_dentry *de;
	u64 d_blocknr = 0;
	int err = -ENOENT;

	pidir = aeon_get_inode(sb, &AEON_I(dir)->header);
	if (!pidir)
		goto out;

	pi = aeon_get_inode(sb, sih);
	if (!pi)
		goto out;

	de = aeon_find_dentry(dest_inode->i_sb, pidir, dir,
			      name->name, name->len);

	dest_inode->i_ctime = current_time(dest_inode);
	inc_nlink(dest_inode);
	pi->i_links_count = cpu_to_le64(dest_inode->i_nlink);
	ihold(dest_inode);

	err = aeon_add_dentry(dentry, dest_inode->i_ino,
			      le64_to_cpu(de->i_blocknr),
			      &d_blocknr, 0);
	if (!err) {
		d_instantiate(dentry, dest_inode);

		aeon_sb->s_num_inodes--;
		aeon_update_super_block_csum(aeon_sb);

		return 0;
	}
	drop_nlink(dest_inode);
	pi->i_links_count = cpu_to_le64(dest_inode->i_nlink);
	iput(dest_inode);

out:
	return err;
}

static int aeon_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);
	struct aeon_inode *pidir;
	struct aeon_inode *pi;
	struct aeon_inode update_dir;
	struct aeon_dentry *remove_entry;
	int ret = -ENOMEM;

	pidir = aeon_get_inode(sb, sih);
	if (!pidir)
		goto out;

	pi = aeon_get_inode(inode->i_sb, &AEON_I(inode)->header);
	if (!pi)
		goto out;

	if (dentry->d_fsdata) {
		remove_entry = (struct aeon_dentry *)dentry->d_fsdata;
		dentry->d_fsdata = NULL;
	} else {
		struct qstr *name = &dentry->d_name;
		remove_entry = aeon_find_dentry(sb, NULL, dir,
						name->name, name->len);
	}

	ret = aeon_remove_dentry(dentry, 0, &update_dir, remove_entry);
	if (ret)
		goto out;

	inode->i_ctime = dir->i_ctime;

	if (inode->i_nlink) {
		drop_nlink(inode);
		pi->i_links_count = cpu_to_le64(inode->i_nlink);
	}

	aeon_sb->s_num_inodes--;
	aeon_update_super_block_csum(aeon_sb);

	return 0;

out:
	aeon_err(sb, "%s return %d\n", __func__, ret);
	return ret;
}

static int aeon_symlink(struct inode *dir,
			struct dentry *dentry,
			const char *symname)
{
	struct super_block *sb = dir->i_sb;
	int err = -ENAMETOOLONG;
	unsigned l = strlen(symname) + 1;
	struct inode *inode;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pi;
	struct aeon_inode *pidir;
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);
	u64 pi_addr = 0;
	u64 i_blocknr = 0;
	u64 d_blocknr = 0;
	u64 ino;

	if (l > sb->s_blocksize)
		goto err;

	pidir = aeon_get_inode(sb, sih);
	if (!pidir)
		goto err;

	ino = aeon_new_aeon_inode(sb, &pi_addr, &i_blocknr);
	if (ino == 0) {
		err = -ENOSPC;
		goto err;
	}

	err = aeon_add_dentry(dentry, ino, i_blocknr, &d_blocknr, 0);
	if (err)
		goto err;

	inode = aeon_new_vfs_inode(TYPE_SYMLINK, dir, pi_addr, ino, S_IFLNK|0777,
				   le32_to_cpu(pidir->aeon_ino), d_blocknr, l, 0,
				   &dentry->d_name);

	si = AEON_I(inode);
	sih = &si->header;
	pi = aeon_get_inode(sb, sih);
	err = aeon_block_symlink(sb, pi, symname, l);
	if (err)
		goto err;

	d_instantiate(dentry, inode);

	aeon_sb->s_num_inodes++;
	aeon_update_super_block_csum(aeon_sb);

	return 0;

err:
	aeon_err(sb, "%s return %d\n", err);
	return err;
}

static int aeon_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode = NULL;
	struct super_block *sb = dir->i_sb;
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pidir;
	u64 ino;
	u64 pi_addr = 0;
	u64 i_blocknr = 0;
	u64 d_blocknr = 0;
	int err = -EMLINK;

	pidir = aeon_get_inode(sb, sih);
	if (!pidir)
		goto out;

	ino = aeon_new_aeon_inode(sb, &pi_addr, &i_blocknr);
	if (ino == 0)
		goto out;

	err = aeon_add_dentry(dentry, ino, i_blocknr, &d_blocknr, 0);

	inode = aeon_new_vfs_inode(TYPE_MKDIR, dir, pi_addr, ino, S_IFDIR | mode,
				   le32_to_cpu(pidir->aeon_ino), d_blocknr,
				   sb->s_blocksize, 0, &dentry->d_name);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	d_instantiate(dentry, inode);

	aeon_sb->s_num_inodes++;
	aeon_update_super_block_csum(aeon_sb);

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
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);
	struct aeon_inode *pi;
	struct aeon_inode update_dir;
	struct aeon_dentry *remove_entry;
	int err = ENOTEMPTY;

	pidir = aeon_get_inode(sb, sih);
	if (!pidir)
		goto out;

	pi = aeon_get_inode(sb, csih);
	if (!pi)
		goto out;

	if (dentry->d_fsdata) {
		remove_entry = (struct aeon_dentry *)dentry->d_fsdata;
		dentry->d_fsdata = NULL;
	} else {
		struct qstr *name = &dentry->d_name;

		if (!aeon_empty_dir(inode))
			return -ENOTEMPTY;
		remove_entry = aeon_find_dentry(sb, NULL, dir,
						name->name, name->len);
	}

	err = aeon_remove_dentry(dentry, -1, &update_dir, remove_entry);
	if (err)
		goto out;

	clear_nlink(inode);
	inode->i_ctime = dir->i_ctime;

	if (dir->i_nlink) {
		drop_nlink(dir);
		pi->i_links_count = cpu_to_le64(dir->i_nlink);
	}

	aeon_sb->s_num_inodes--;
	aeon_update_super_block_csum(aeon_sb);

	return 0;

out:
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
	struct aeon_inode *update;
	struct qstr *old_name = &old_dentry->d_name;
	struct qstr *new_name = &new_dentry->d_name;
	u64 d_blocknr = 0;
	int err;

	if (old_dentry->d_fsdata) {
		old_de = (struct aeon_dentry *)old_dentry->d_fsdata;
		old_dentry->d_fsdata = NULL;
	} else
		old_de = aeon_find_dentry(sb, pi, old_dir,
					  old_name->name, old_name->len);
	if (old_de == NULL) {
		err = -ENOENT;
		goto out_dir;
	}

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
		dir_de = aeon_dotdot(sb, old_dentry);
		if (!dir_de)
			goto out_dir;
	}

	if (new_inode) {
		err = -ENOTEMPTY;
		if (dir_de && !aeon_empty_dir(new_inode))
			goto out_dir;

		err = -ENOENT;
		new_de = aeon_find_dentry(sb, NULL, new_dir,
					  new_name->name, new_name->len);
		if (!new_de)
			goto out_dir;
		aeon_set_link(new_dir, new_de, old_inode, 1);
		new_inode->i_ctime = current_time(new_inode);
		if (dir_de)
			drop_nlink(new_inode);
		drop_nlink(new_inode);
		update = aeon_get_inode(new_inode->i_sb,
					&AEON_I(new_inode)->header);
		update->i_links_count = cpu_to_le64(new_inode->i_nlink);
	} else {
		err = aeon_add_dentry(new_dentry, le32_to_cpu(old_inode->i_ino),
				      le64_to_cpu(old_de->i_blocknr),
				      &d_blocknr, 0);
		pi->i_dentry_block = cpu_to_le64(d_blocknr);
		if (err)
			goto out_dir;
		if (dir_de)
			inc_nlink(new_dir);
	}

	old_inode->i_ctime = current_time(old_inode);
	aeon_remove_dentry(old_dentry, 0, pi, old_de);

	if (dir_de) {
		if (old_dir != new_dir)
			aeon_set_link(old_inode, dir_de, new_dir, 0);
		drop_nlink(old_dir);
		update = aeon_get_inode(old_dir->i_sb,
					&AEON_I(old_dir)->header);
		update->i_links_count = cpu_to_le64(old_dir->i_nlink);
	}

	return 0;

out_dir:
	aeon_err(sb, "%s return %d\n", __func__, err);
	return err;
}

static int aeon_mknod(struct inode *dir, struct dentry *dentry,
		      umode_t mode, dev_t rdev)
{
	struct super_block *sb = dir->i_sb;
	struct aeon_inode *pidir;
	struct aeon_super_block *aeon_sb = aeon_get_super(dir->i_sb);
	struct inode *inode = NULL;
	u64 pi_addr = 0;
	u64 i_blocknr = 0;
	u64 d_blocknr = 0;
	u32 ino;
	int err = PTR_ERR(inode);

	pidir = aeon_get_inode(sb, &AEON_I(dir)->header);
	if (!pidir)
		goto out;

	ino = aeon_new_aeon_inode(sb, &pi_addr, &i_blocknr);
	if (ino == 0)
		goto out;

	err = aeon_add_dentry(dentry, ino, i_blocknr, &d_blocknr, 0);
	if (err)
		goto out;

	inode = aeon_new_vfs_inode(TYPE_MKNOD, dir, pi_addr, ino, mode,
				   le32_to_cpu(pidir->aeon_ino),
				   d_blocknr, 0, rdev, &dentry->d_name);
	if (IS_ERR(inode))
		goto out;

	d_instantiate(dentry, inode);

	aeon_sb->s_num_inodes++;
	aeon_update_super_block_csum(aeon_sb);

	return 0;

out:
	return err;
}

static int aeon_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	struct aeon_inode *pidir;
	u64 pi_addr;
	u32 ino;

	pidir = aeon_get_inode(dir->i_sb, &AEON_I(dir)->header);
	if (!pidir)
		return -ENOENT;

	ino = aeon_new_aeon_inode(dir->i_sb, &pi_addr, NULL);
	if (ino == 0)
		return -ENOSPC;

	inode = aeon_new_vfs_inode(TYPE_CREATE, dir, pi_addr, ino, mode,
				   le32_to_cpu(pidir->aeon_ino),
				   0, 0, 0, &dentry->d_name);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	aeon_set_file_ops(inode);
	d_tmpfile(dentry, inode);

	return 0;
}

const struct inode_operations aeon_dir_inode_operations = {
	.create		= aeon_create,
	.lookup		= aeon_lookup,
	.link		= aeon_link,
	.unlink		= aeon_unlink,
	.symlink	= aeon_symlink,
	.mkdir		= aeon_mkdir,
	.rmdir		= aeon_rmdir,
	.rename		= aeon_rename,
	.mknod		= aeon_mknod,
	.setattr	= aeon_setattr,
	.get_acl	= NULL,
	.tmpfile	= aeon_tmpfile,
};

const struct inode_operations aeon_special_inode_operations = {
	.setattr = aeon_setattr,
	.get_acl = NULL,
};
