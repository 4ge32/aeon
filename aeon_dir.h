#ifndef __AEON_DENTRY_H
#define __AEON_DENTRY_H

#define AEON_NAME_LEN		128
#define AEON_DENTRY_SIZE        (1 << AEON_D_SHIFT)
#define AEON_DENTRY_CSIZE       ((1 << AEON_D_SHIFT) - CHECKSUM_SIZE)
#define AEON_INTERNAL_ENTRY     ((AEON_DEF_BLOCK_SIZE_4K / AEON_DENTRY_SIZE) * \
							 AEON_PAGES_FOR_DENTRY)
#define MAX_ENTRY               502
#define MAX_DENTRY              ((MAX_ENTRY << AEON_D_SHIFT ) + \
		                ((MAX_ENTRY - 1 ) << AEON_D_SHIFT))
#define AEON_DENTRY_MAP_SIZE	AEON_DEF_BLOCK_SIZE_4K
#define AEON_DENTRY_MAP_CSIZE	(AEON_DENTRY_MAP_SIZE - CHECKSUM_SIZE)

struct aeon_dentry_invalid {
	struct list_head invalid_list;
	struct aeon_dentry *d_addr;
};

struct aeon_dentry_map {
	unsigned long  block_dentry[MAX_ENTRY];
	unsigned long  next_map;
	unsigned long  num_dentries;
	unsigned int  num_latest_dentry;
	unsigned int  num_internal_dentries;
	bool first;
};

struct aeon_dentry_candidate {
	struct list_head list;
	struct aeon_dentry *d;
};

/*
 * Structure of an private dentry info on dram
 */
struct aeon_dentry_info {
	spinlock_t de_lock;
	struct mutex dentry_mutex;
	struct aeon_dentry_invalid *di;
	struct aeon_dentry_map de_map;
	struct aeon_dentry_candidate *adc;
};

/*
 * Structure of an dentry on pmem
 */
struct aeon_dentry {
	u8	name_len;		/* length of the dentry name */
	u8	valid;			/* Invalid now? */
	u8	persisted;		/* fully persisted? */

	__le16	d_mode;			/* duplicated mode */
	__le16	d_size;			/* duplicated size */
	/* duplicated rdev */
	struct {
		__le32 rdev;	 /* major/minor # */
	} dev;			 /* device inode */

	__le32	ino;
	__le64	d_pinode_addr;
	__le64	d_inode_addr;
	__le64	d_dentry_addr;

	__le64	d_prev_dentry_block;
	__le64	d_this_dentry_block;
	__le64	d_next_dentry_block;

	/* 128 bytes */
	char	name[AEON_NAME_LEN+1];  /* File name */
	/* padding */
	char	pad[60];
	__le32	csum;			/* entry checksum */
} __attribute((__packed__));


// BKDR String Hash Function
static inline unsigned long BKDRHash(const char *str, int length)
{
	unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
	unsigned long hash = 0;
	int i;

	for (i = 0; i < length; i++)
		hash = hash * seed + (*str++);

	return hash;
}

static inline int is_persisted_dentry(struct aeon_dentry *de)
{
	__le32 temp;

	temp = cpu_to_le32(crc32_le(SEED,
				    (unsigned char *)de,
				    AEON_DENTRY_CSIZE));
	if (temp != de->csum)
		return 0;

	return 1;
}

static inline void aeon_update_dentry_csum(struct aeon_dentry *de)
{
	de->csum = cpu_to_le32(crc32_le(SEED,
			       (unsigned char *)de,
			       AEON_DENTRY_CSIZE));
}

#include "aeon_inode.h"
static inline
struct aeon_dentry_map *aeon_get_dentry_map(struct super_block *sb,
					    struct aeon_inode_info_header *sih)
{
	if (!sih->de_info)
		return NULL;

	return &sih->de_info->de_map;

}

static inline
u64 aeon_get_dentry_tb_head(struct super_block *sb, struct aeon_inode *pidir)
{
	u64 ret = le64_to_cpu(pidir->i_dentry_table_block);
	if (ret < 0 || AEON_SB(sb)->num_blocks <= ret)
		/* There is no possibility that an dentry table block would be zero */
		return 0;
	return ret;
}


int aeon_insert_dir_tree(struct super_block *sb,
			 struct aeon_inode_info_header *sih,
			 const char *name, int namelen,
			 struct aeon_dentry *direntry);
int aeon_add_dentry(struct dentry *dentry, struct aeon_mdata *am);
int aeon_remove_dentry(struct dentry *dentry, int dec_link,
		       struct aeon_inode *update, struct aeon_dentry *de);
int aeon_get_dentry_address(struct super_block *sb,
			    struct aeon_inode *pi, u64 *de_addr);
struct aeon_dentry *aeon_find_dentry(struct super_block *sb,
				     struct aeon_inode *pi,
				     struct inode *inode, const char *name,
				     unsigned long name_len);
int aeon_delete_dir_tree(struct super_block *sb,
			 struct aeon_inode_info_header *sih);
struct aeon_dentry *aeon_dotdot(struct super_block *sb,
				struct dentry *dentry);
void aeon_set_link(struct inode *dir, struct aeon_dentry *de,
		   struct inode *inode, int update_times);
void aeon_set_pdir_link(struct aeon_dentry *de, struct aeon_inode *pi,
			struct inode *new_dir);
int aeon_empty_dir(struct inode *inode);
int aeon_free_cached_dentry_blocks(struct super_block *sb,
				   struct aeon_inode_info_header *sih);
void aeon_free_invalid_dentry_list(struct super_block *sb,
				   struct aeon_inode_info_header *sih);

#endif
