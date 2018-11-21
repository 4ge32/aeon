#include <linux/rwsem.h>
#include <linux/mbcache.h>
#include <linux/quotaops.h>

#include "aeon.h"
#include "xattr.h"

static inline
struct aeon_xattr_header *HDR(struct super_block *sb, u64 blocknr)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return (struct aeon_xattr_header *)((u64)sbi->virt_addr +
					   (blocknr << AEON_SHIFT));
}

static inline
struct aeon_xattr_header *_HDR(u64 addr)
{
	return (struct aeon_xattr_header *)addr;
}

static inline
struct aeon_xattr_entry *ENTRY(struct super_block *sb, u64 blocknr, int offset)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return (struct aeon_xattr_entry *)((u64)sbi->virt_addr +
					   (blocknr << AEON_SHIFT) + offset);
}

static inline
struct aeon_xattr_entry *FIRST_ENTRY(struct super_block *sb, u64 blocknr) {
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return (struct aeon_xattr_entry *)((u64)sbi->virt_addr +
					   (blocknr << AEON_SHIFT) +
					   sizeof(struct aeon_xattr_header));
}

static inline
struct aeon_xattr_entry *_FIRST_ENTRY(u64 addr)
{
	return (struct aeon_xattr_entry *)(addr +
					   sizeof(struct aeon_xattr_header));
}

static inline
struct aeon_xattr_entry *LAST_ENTRY(struct super_block *sb, u64 blocknr) {
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return (struct aeon_xattr_entry *)((u64)sbi->virt_addr +
					   ((blocknr + 1) << AEON_SHIFT));
}

#define _ENTRY(xattr) ((struct aeon_xattr_entry *)xattr)
#define IS_LAST_ENTRY(entry) (*(__u32 *)(entry) == 0)
#define AEON_XATTR_PAD_BITS	2
#define AEON_XATTR_PAD		(1<<AEON_XATTR_PAD_BITS)
#define AEON_XATTR_ROUND	(AEON_XATTR_PAD-1)
#define AEON_XATTR_LEN(name_len) \
	(((name_len) + AEON_XATTR_ROUND + \
	sizeof(struct aeon_xattr_entry)) & ~AEON_XATTR_ROUND)
#define AEON_XATTR_NEXT(entry) \
	( (struct aeon_xattr_entry *)( \
	  (char *)(entry) + AEON_XATTR_LEN((entry)->e_name_len)) )
#define AEON_XATTR_SIZE(size) \
	(((size) + AEON_XATTR_ROUND) & ~AEON_XATTR_ROUND)

static int aeon_xattr_set2(struct inode *, u64,
			   struct aeon_xattr_header *);
static int aeon_xattr_cache_insert(struct mb_cache *, struct super_block *sb,
				   u64 blocknr);
static u64 aeon_xattr_cache_find(struct inode *, struct aeon_xattr_header *);
static void aeon_xattr_rehash(struct aeon_xattr_header *,
			      struct aeon_xattr_entry *);

static const struct xattr_handler *aeon_xattr_handler_map[] = {
	[AEON_XATTR_INDEX_USER]		     = &aeon_xattr_user_handler,
#ifdef CONFIG_AEON_FS_POSIX_ACL
	[AEON_XATTR_INDEX_POSIX_ACL_ACCESS]  = &posix_acl_access_xattr_handler,
	[AEON_XATTR_INDEX_POSIX_ACL_DEFAULT] = &posix_acl_default_xattr_handler,
#endif
	//[AEON_XATTR_INDEX_TRUSTED]	     = &aeon_xattr_trusted_handler,
#ifdef CONFIG_AEON_FS_SECURITY
	//[AEON_XATTR_INDEX_SECURITY]	     = &aeon_xattr_security_handler,
#endif
};

#define EA_BLOCK_CACHE(inode)	(AEON_SB(inode->i_sb)->s_ea_block_cache)

const struct xattr_handler *aeon_xattr_handlers[] = {
	&aeon_xattr_user_handler,
	//&aeon_xattr_trusted_handler,
#ifdef CONFIG_AEON_FS_POSIX_ACL
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
#endif
#ifdef CONFIG_AEON_FS_SECURITY
	//&aeon_xattr_security_handler,
#endif
	NULL
};

static inline const struct xattr_handler *aeon_xattr_handler(int name_index)
{
	const struct xattr_handler *handler = NULL;

	if (name_index > 0 && name_index < ARRAY_SIZE(aeon_xattr_handler_map))
		handler = aeon_xattr_handler_map[name_index];
	return handler;
}

int aeon_xattr_get(struct inode *inode, int name_index, const char *name,
		   void *buffer, size_t buffer_size)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_xattr_header *header;
	struct aeon_xattr_entry *entry;
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	size_t name_len;
	size_t size;
	char *end = NULL;
	int err;
	struct mb_cache *ea_block_cache = EA_BLOCK_CACHE(inode);
	u64 blocknr;

	aeon_dbg("name=%d.%s, buffer=%p, buffer_size=%ld\n",
		 name_index, name, buffer, (long)buffer_size);

	if (name == NULL)
		return -EINVAL;
	name_len = strlen(name);
	if (name_len > 255)
		return -ERANGE;

	down_read(&sih->xattr_sem);
	err = -ENODATA;
	if (!pi->i_xattr)
		goto cleanup;
	blocknr = le64_to_cpu(pi->i_xattr);
	header = HDR(sb, blocknr);
	end = (char *)LAST_ENTRY(sb, blocknr);
	if (header->h_magic != cpu_to_le32(AEON_XATTR_MAGIC) ||
	    header->h_blocks != cpu_to_le32(1)) {
bad_block:
		aeon_err(sb, "aeon_xattr_get inode %ld: bad block %d\n",
			 inode->i_ino, pi->i_xattr);
		err = EIO;
		goto cleanup;
	}

	entry = FIRST_ENTRY(sb, blocknr);
	while (!IS_LAST_ENTRY(entry)) {
		struct aeon_xattr_entry *next = AEON_XATTR_NEXT(entry);
		if ((char *)next >= end)
			goto bad_block;
		if (name_index == entry->e_name_index &&
		    name_len == entry->e_name_len &&
		    memcmp(name, entry->e_name, name_len) == 0)
			goto found;
		entry = next;
	}
	if (aeon_xattr_cache_insert(ea_block_cache, sb, blocknr))
		aeon_dbg("cache insert failed");
	err = -ENODATA;
	goto cleanup;
found:
	if (entry->e_value_block != 0)
		goto bad_block;
	size = le32_to_cpu(entry->e_value_size);
	if (size > sb->s_blocksize ||
	    le16_to_cpu(entry->e_value_offs) + size > sb->s_blocksize)
		goto bad_block;

	if (aeon_xattr_cache_insert(ea_block_cache, sb, blocknr))
		aeon_dbg("cache insert failed");
	if (buffer) {
		err = -ERANGE;
		if (size > buffer_size)
			goto cleanup;
	}
	err = size;
cleanup:
	up_read(&sih->xattr_sem);

	return err;
}

int aeon_xattr_set(struct inode *inode, int name_index, const char *name,
		   const void *value, size_t value_len, int flags)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_xattr_header *header = NULL;
	struct aeon_xattr_entry *here;
	struct aeon_xattr_entry *last;
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	size_t name_len;
	size_t free;
	size_t min_offs = sb->s_blocksize;
	char *end;
	bool not_found = true;
	int err;
	u64 xattr = 0;

	if (value == NULL)
		value_len = 0;
	if (name == NULL)
		return -EINVAL;
	name_len = strlen(name);
	if (name_len > 255 || value_len > sb->s_blocksize)
		return -ERANGE;

	down_write(&sih->xattr_sem);
	xattr = le64_to_cpu(pi->i_xattr);
	if (!xattr) {
		u64 addr;
		xattr = aeon_get_xattr_blk(sb);
		pi->i_xattr = cpu_to_le64(xattr);
		addr = (u64)AEON_SB(sb)->virt_addr + xattr;
		header = (struct aeon_xattr_header *)addr;
		header->h_magic = cpu_to_le32(AEON_XATTR_MAGIC);
		header->h_blocks = cpu_to_le32(1);
		rwlock_init(&header->x_lock);
	}

	xattr = (u64)AEON_SB(sb)->virt_addr + xattr;
	if (xattr) {
		/* Check whether header is valid or not. */
		header = _HDR(xattr);
		end = (char *)(xattr + (1<<AEON_SHIFT));
		if (header->h_magic != cpu_to_le32(AEON_XATTR_MAGIC) ||
		    header->h_blocks != cpu_to_le32(1)) {
bad_block:
			aeon_err(sb, "%s inode %ld: bad addr 0x%llx",
				 __func__, inode->i_ino, xattr);
			err = -EIO;
			goto cleanup;
		}

		/* Find the named attribute. */
		here = _FIRST_ENTRY(xattr);
		while (!IS_LAST_ENTRY(here)) {
			struct aeon_xattr_entry *next = AEON_XATTR_NEXT(here);
			if ((char *)next >= end)
				goto bad_block;
			if (!here->e_value_block && here->e_value_size) {
				size_t offs = le16_to_cpu(here->e_value_offs);
				if (offs < min_offs)
					min_offs = offs;
			}
			not_found = name_index - here->e_name_index;
			if (!not_found)
				not_found = name_len - here->e_name_len;
			if (!not_found)
				not_found = memcmp(name, here->e_name, name_len);
			if (not_found <= 0)
				break;
			here = next;
		}
		last = here;

		while (!IS_LAST_ENTRY(last)) {
			struct aeon_xattr_entry *next = AEON_XATTR_NEXT(last);
			if ((char *)next >= end)
				goto bad_block;
			if (!last->e_value_block && last->e_value_offs) {
				size_t offs = le16_to_cpu(last->e_value_offs);
				if (offs < min_offs)
					min_offs = offs;
			}
			last = next;
		}

		/* Check whether we have enough space left. */
		free = min_offs - ((char *)last - (char *)header) - sizeof(__u32);
	} else {
		/* We will use a new extended attribute block. */
		free = sb->s_blocksize -
			sizeof(struct aeon_xattr_header) - sizeof(__u32);
		here = last = NULL;
	}

	if (not_found) {
		/* Request to remove a nonexistent attribute? */
		err = -ENODATA;
		if (flags & XATTR_REPLACE)
			goto cleanup;
		err = 0;
		if (value == NULL)
			goto cleanup;
	} else {
		/* Request to create an existing attribute? */
		err = -EEXIST;
		if (flags & XATTR_CREATE)
			goto cleanup;
		if (!here->e_value_block && here->e_value_size) {
			size_t size = le32_to_cpu(here->e_value_size);

			if (le16_to_cpu(here->e_value_offs) + size >
			    sb->s_blocksize || size > sb->s_blocksize)
				goto bad_block;
			free += AEON_XATTR_LEN(size);
		}
		free += AEON_XATTR_LEN(name_len);
	}
	err = ENOSPC;
	if (free < AEON_XATTR_LEN(name_len) + AEON_XATTR_SIZE(value_len))
		goto cleanup;

	/* Here we know that we can set the new attribute. */

	if (header) {
		if (header->h_refcount == cpu_to_le32(1)) {
			__u32 hash = le32_to_cpu(header->h_hash);

			aeon_info("modifying in-place\n");
			mb_cache_entry_delete(EA_BLOCK_CACHE(inode), hash,
					      0);
		} else {
			int offset;

			header = kmalloc((1<<AEON_SHIFT), GFP_KERNEL);
			err = -ENOMEM;
			if (header == NULL)
				goto cleanup;

			/*
			 * can it be improved?
			 */
			memcpy(header, _HDR(xattr), 1<<AEON_SHIFT);
			header->h_refcount = cpu_to_le32(1);

			offset = (char *)here - (char *)_FIRST_ENTRY(xattr);
			here = _ENTRY((char *)header + offset);
			offset = (char *)last - (char *)_FIRST_ENTRY(xattr);
			last = _ENTRY((char *)xattr + offset);
		}
	} else {
		/* Allocate a buffer where we construct the new block. */
		header = kzalloc(sb->s_blocksize, GFP_KERNEL);
		err = -ENOMEM;
		if (header == NULL)
			goto cleanup;
		end = (char *)header + sb->s_blocksize;
		header->h_magic = cpu_to_le32(AEON_XATTR_MAGIC);
		header->h_blocks = header->h_refcount = cpu_to_le32(1);
		last = here = _ENTRY(header+1);
	}

	/* Iff we are modifying the block in-place, xattr obj is locked here. */

	if (not_found) {
		/* Insert the new name */
		size_t size = AEON_XATTR_LEN(name_len);
		size_t rest = (char *)last - (char *)here;
		memmove((char *)here + size, here, rest);
		memset(here, 0, size);
		here->e_name_index = name_index;
		here->e_name_len = name_len;
		memcpy(here->e_name, name, name_len);
	} else {
		if (!here->e_value_block && here->e_value_size) {
			char *first_val = (char *)header + min_offs;
			size_t offs = le16_to_cpu(here->e_value_offs);
			char *val = (char *)header + offs;
			size_t size = AEON_XATTR_SIZE(
				le32_to_cpu(here->e_value_size));

			if (size == AEON_XATTR_SIZE(value_len)) {
				here->e_value_size = cpu_to_le32(value_len);
				memset(val + size - AEON_XATTR_PAD, 0,
				       AEON_XATTR_PAD); /* Clear pad bytes. */
				memcpy(val, value, value_len);
				goto skip_replace;
			}

			/* Remove the old value */
			memmove(first_val + size, first_val, val - first_val);
			memset(first_val, 0, size);
			here->e_value_offs = 0;
			min_offs += size;

			/* Adjust all value offsets. */
			last = _ENTRY(header+1);
			while (!IS_LAST_ENTRY(last)) {
				size_t o = le16_to_cpu(last->e_value_offs);
				if (!last->e_value_block && o < offs)
					last->e_value_offs =
						cpu_to_le16(o + size);
				last = AEON_XATTR_NEXT(last);
			}
		}
		if (value == NULL) {
			size_t size = AEON_XATTR_LEN(name_len);
			last = _ENTRY((char *)last - size);
			memmove(here, (char *)here + size,
				(char *)last - (char *)here);
			memset(last, 0, size);
		}
	}

	if (value != NULL) {
		/* Insert the new value */
		here->e_value_size = cpu_to_le32(value_len);
		if (value_len) {
			size_t size = AEON_XATTR_SIZE(value_len);
			char *val = (char *)header + min_offs - size;
			here->e_value_offs =
				cpu_to_le16((char *)val - (char *)header);
			memset(val + size - AEON_XATTR_PAD, 0, AEON_XATTR_PAD);
			memcpy(val, value, value_len);
		}
	}

skip_replace:
	if (IS_LAST_ENTRY(_ENTRY(header+1))) {
		err = aeon_xattr_set2(inode, xattr, NULL);
		// not set next block
	} else {
		aeon_xattr_rehash(header, here);
		err = aeon_xattr_set2(inode, xattr, header);
	}

cleanup:
	up_write(&sih->xattr_sem);

	return err;
}

static int
aeon_xattr_set2(struct inode *inode, u64 addr,
		struct aeon_xattr_header *header)
{
	//struct super_block *sb = inode->i_sb;
	u64 new_addr;
	int err;
	//struct mb_cache *ea_block_cache = EA_BLOCK_CACHE(inode);

	if (header) {
		new_addr = aeon_xattr_cache_find(inode, header);
		if (new_addr) {
			/* We found an identical block in the cache */
			if (new_addr == addr)
				aeon_dbg("Keeping this block\n");
			else {
				/* The old block is released after updating
				   the inode */
				aeon_dbg("reusing block\n");

				err = dquot_alloc_block(inode, 1);
			}
		} else if (addr && header == _HDR(addr)) {
		} else {
		}
	 }
	return 0;
}

static int
aeon_xattr_cache_insert(struct mb_cache *cache,
			struct super_block *sb, u64 blocknr)
{
	__u32 hash = le32_to_cpu(HDR(sb, blocknr)->h_hash);
	int err;

	err = mb_cache_entry_create(cache, GFP_NOFS, hash, blocknr, 1);
	if (err) {
		if (err == -EBUSY) {
			err = 0;
		}
	}

	return err;
}

static u64
aeon_xattr_cache_find(struct inode *inode, struct aeon_xattr_header *header)
{
	return 0;
}


#define NAME_HASH_SHIFT 5
#define VALUE_HASH_SHIFT 16

static inline void aeon_xattr_hash_entry(struct aeon_xattr_header *header,
					 struct aeon_xattr_entry *entry)
{
	__u32 hash = 0;
	char *name = entry->e_name;
	int n;

	for (n = 0; n < entry->e_name_len; n++) {
		hash = (hash << NAME_HASH_SHIFT) ^
			(hash >> (8*sizeof(hash) - NAME_HASH_SHIFT)) ^
			*name++;
	}

	if (entry->e_value_block == 0 && entry->e_value_size != 0) {
		__le32 *value = (__le32 *)((char *)header +
					   le16_to_cpu(entry->e_value_offs));
		for (n = (le32_to_cpu(entry->e_value_size) +
		     AEON_XATTR_ROUND) >> AEON_XATTR_PAD_BITS; n; n--) {
			hash = (hash << VALUE_HASH_SHIFT) ^
			       (hash >> (8*sizeof(hash) - VALUE_HASH_SHIFT)) ^
			       le32_to_cpu(*value++);
		}
	}
	entry->e_hash = cpu_to_le32(hash);
}

#undef NAME_HASH_SHIFT
#undef VALUE_HASH_SHIFT

#define BLOCK_HASH_SHIFT 16

static void aeon_xattr_rehash(struct aeon_xattr_header *header,
			      struct aeon_xattr_entry *entry)
{
	aeon_xattr_hash_entry(header, entry);
}

#undef BLOCK_HASH_SHIFT

#define HASH_BUCKET_BITS 10

struct mb_cache *aeon_xattr_create_cache(void)
{
	return mb_cache_create(HASH_BUCKET_BITS);
}

void aeon_xattr_destroy_cache(struct mb_cache *cache)
{
	if (cache)
		mb_cache_destroy(cache);
}
