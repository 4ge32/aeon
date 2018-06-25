#include <linux/fs.h>
#include <linux/pagemap.h>

#include "aeon.h"
#include "super.h"
#include "inode.h"
#include "balloc.h"
#include "dir.h"

static int aeon_create(struct inode *dir, struct dentry *dentry, umode_t mode,
			bool excl)
{
	struct aeon_inode *pidir;
	struct super_block *sb = dir->i_sb;
	struct inode *inode = NULL;
	u64 pi_addr = 0;
	u64 ino;
	int err = PTR_ERR(inode);

	aeon_dbg("%s: START\n", __func__);
	pidir = aeon_get_inode(sb, dir);
	aeon_dbg("%s: START\n", __func__);
	ino = aeon_new_aeon_inode(sb, &pi_addr);
	if (ino == 0)
		goto out;

	aeon_dbg("%s: START\n", __func__);
	err = aeon_add_dentry(dentry, ino, 0);
	if (err)
		goto out;

	aeon_dbg("%s: START\n", __func__);
	inode = aeon_new_vfs_inode(TYPE_CREATE, dir, pi_addr, ino, mode, 0, 0, &dentry->d_name);
	if (IS_ERR(inode))
		goto out;

	d_instantiate(dentry, inode);
	//unlock_new_inode(inode);

	aeon_dbg("%s: 0x%llx", __func__, pi_addr);

	aeon_dbg("%s: FINISH\n", __func__);
	return 0;
out:
	aeon_err(sb, "%s return %d\n", __func__, err);
	return err;
}

struct dentry *aeon_lookup(struct inode *dir, struct dentry *dentry, unsigned int flag)
{
	struct inode *inode = NULL;
	ino_t ino;

	ino = aeon_inode_by_name(dir, &dentry->d_name);

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

const struct inode_operations aeon_dir_inode_operations = {
	.create = aeon_create,
	.lookup = aeon_lookup,
	//.unlink = aeon_unlink,
};
