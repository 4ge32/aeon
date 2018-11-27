#include "aeon.h"
#include "xattr.h"

static bool
aeon_xattr_trusted_list(struct dentry *dentry)
{
	return capable(CAP_SYS_ADMIN);
}

static int
aeon_xattr_trusted_get(const struct xattr_handler *handler,
		       struct dentry *unused, struct inode *inode,
		       const char *name, void *buffer, size_t size)
{
	return aeon_xattr_get(inode, AEON_XATTR_INDEX_TRUSTED, name,
			      buffer, size);
}

static int
aeon_xattr_trusted_set(const struct xattr_handler *handler,
		       struct dentry *unused, struct inode *inode,
		       const char *name, const void *value,
		       size_t size, int flags)
{
	return aeon_xattr_set(inode, AEON_XATTR_INDEX_TRUSTED, name,
			      value, size, flags);
}

const struct xattr_handler aeon_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= aeon_xattr_trusted_list,
	.get	= aeon_xattr_trusted_get,
	.set	= aeon_xattr_trusted_set,
};
