#include <linux/security.h>
#include "aeon.h"
#include "xattr.h"

static int
aeon_xattr_security_get(const struct xattr_handler *handler,
			struct dentry *unused, struct inode *inode,
			const char *name, void *buffer, size_t size)
{
	return aeon_xattr_get(inode, AEON_XATTR_INDEX_SECURITY, name,
			      buffer, size);
}

static int
aeon_xattr_security_set(const struct xattr_handler *handler,
			struct dentry *unused, struct inode *inode,
			const char *name, const void *value,
			size_t size, int flags)
{
	return aeon_xattr_set(inode, AEON_XATTR_INDEX_SECURITY, name,
			      value, size, flags);
}

static int
aeon_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		void *fs_info)
{
	const struct xattr *xattr;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = aeon_xattr_set(inode, AEON_XATTR_INDEX_SECURITY,
				     xattr->name, xattr->value,
				     xattr->value_len, 0);
		if (err < 0)
			break;
	}
	return err;
}

int
aeon_init_security(struct inode *inode, struct inode *dir,
		   const struct qstr *qstr)
{
	return security_inode_init_security(inode, dir, qstr,
					    &aeon_initxattrs, NULL);
}

const struct xattr_handler aeon_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.get	= aeon_xattr_security_get,
	.set	= aeon_xattr_security_set,
};
