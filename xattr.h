#include <linux/init.h>
#include <linux/xattr.h>

/* Magic value in attribute blocks */
#define AEON_XATTR_MAGIC		0xEFF20

/* Maximum number of references to one attribute block */
#define AEON_XATTR_REFCOUNT_MAX		1024

/* Name indexes */
#define AEON_XATTR_INDEX_USER			1
#define AEON_XATTR_INDEX_POSIX_ACL_ACCESS	2
#define AEON_XATTR_INDEX_POSIX_ACL_DEFAULT	3
#define AEON_XATTR_INDEX_TRUSTED		4
#define	AEON_XATTR_INDEX_LUSTRE			5
#define AEON_XATTR_INDEX_SECURITY	        6

struct aeon_xattr_header {
	rwlock_t   x_lock;
	__le32     h_magic;		/* magic number for identification */
	__le32	   h_refcount;		/* reference count */
	__le32	   h_blocks;		/* number of disk blocks used */
	__le32	   h_hash;		/* hash value of all attributes */
	__u32	   h_reserved[4];	/* zero right now */
};

struct aeon_xattr_entry {
	__u8	e_name_len;	/* length of name */
	__u8	e_name_index;	/* attribute name index */
	__le16	e_value_offs;	/* offset in disk block of value */
	__le32	e_value_block;	/* disk block attribute is stored on (n/i) */
	__le32	e_value_size;	/* size of attribute value */
	__le32	e_hash;		/* hash value of name and value */
	char	e_name[0];	/* attribute name */
};


struct mb_cache;

#ifdef CONFIG_AEON_FS_XATTR

extern const struct xattr_handler aeon_xattr_user_handler;
extern const struct xattr_handler aeon_xattr_trusted_handler;
extern const struct xattr_handler aeon_xattr_security_handler;

extern ssize_t aeon_listxattr(struct dentry *, char *, size_t);

extern int aeon_xattr_get(struct inode *, int, const char *, void *, size_t);
extern int aeon_xattr_set(struct inode *, int, const char *,
			  const void *, size_t, int);

extern void aeon_xattr_delete_inode(struct inode *);

extern struct mb_cache *aeon_xattr_create_cache(void);
extern void aeon_xattr_destroy_cache(struct mb_cache *cache);

extern const struct xattr_handler *aeon_xattr_handlers[];

#else

static inline int
aeon_xattr_get(struct inode *inode, int name_index,
	       const char *name, void *buffer, size_t size)
{
	return -EOPNOTSUPP;
}

static inline int
aeon_xattr_set(struct inode *inode, int name_index, const char *name,
	       const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
}

static inline void
aeon_xattr_delete_inode(struct inode *inode)
{
}

static inline void aeon_xattr_destroy_cache(struct mb_cache *cache)
{
}

#define aeon_xattr_handlers NULL

#endif

#ifdef CONFIG_AEON_FS_SECURITY
extern int aeon_init_security(struct inode *inode, struct inode *dir,
			      const struct qstr *qstr);
#else
static inline int aeon_init_security(struct inode *inode, struct inode *dir,
				     const struct qstr *qstr)
{
	return 0;
}
#endif
