#include <linux/init.h>
#include <linux/string.h>

#include "aeon.h"
#include "xattr.h"

static bool aeon_xattr_user_list(struct dentry *dentry)
{
	return test_opt(dentry->d_sb, XATTR_USER);
}

static int aeon_xattr_user_get(const struct xattr_handler *handler,
			       struct dentry *unused, struct inode *inode,
			       const char *name, void *buffer, size_t size)
{
	if (!test_opt(inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;

	return aeon_xattr_get(inode, AEON_XATTR_INDEX_USER,
			      name, buffer, size);
}

static int aeon_xattr_user_set(const struct xattr_handler *handler,
			       struct dentry *unused, struct inode *inode,
			       const char *name, const void *value,
			       size_t size, int flags)
{
	if (!test_opt(inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;

	return aeon_xattr_set(inode, AEON_XATTR_INDEX_USER,
			      name, value, size, flags);
}

const struct xattr_handler aeon_xattr_user_handler = {
	.prefix = XATTR_USER_PREFIX,
	.list	= aeon_xattr_user_list,
	.get	= aeon_xattr_user_get,
	.set	= aeon_xattr_user_set,
};
