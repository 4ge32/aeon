#ifndef _LINUX_AEON_FS_H
#define _LINUX_AEON_FS_H

#include <linux/types.h>
#include <linux/magic.h>

#define AEON_MAGIC 0xEFF10

/* manual */
#define AEON_I_SHIFT            8
#define AEON_D_SHIFT            8
#define AEON_PAGES_FOR_INODE    1
#define AEON_PAGES_FOR_DENTRY   1
#define SEED			131

/* auto */
#define CHECKSUM_SIZE		4
#define AEON_INODE_SIZE         (1 << AEON_I_SHIFT)
#define AEON_INODE_CSIZE        (AEON_INODE_SIZE - CHECKSUM_SIZE)
#define AEON_SB_SIZE            512
#define AEON_SB_CSIZE           (512 - CHECKSUM_SIZE)
#define AEON_SHIFT              12
#define AEON_DEF_BLOCK_SIZE_4K  (1 << AEON_SHIFT)
#define AEON_I_NUM_PER_PAGE     ((AEON_DEF_BLOCK_SIZE_4K / AEON_INODE_SIZE) * \
							AEON_PAGES_FOR_INODE)
#define AEON_NAME_LEN		128
#define AEON_DENTRY_SIZE        (1 << AEON_D_SHIFT)
#define AEON_DENTRY_CSIZE       ((1 << AEON_D_SHIFT) - CHECKSUM_SIZE)
#define AEON_INTERNAL_ENTRY     ((AEON_DEF_BLOCK_SIZE_4K / AEON_DENTRY_SIZE) * \
							 AEON_PAGES_FOR_DENTRY)
#define MAX_ENTRY               507
#define MAX_DENTRY              ((MAX_ENTRY << AEON_D_SHIFT ) + \
		                ((MAX_ENTRY - 1 ) << AEON_D_SHIFT))
#define AEON_DENTRY_MAP_SIZE	AEON_DEF_BLOCK_SIZE_4K
#define AEON_DENTRY_MAP_CSIZE	(AEON_DENTRY_MAP_SIZE - CHECKSUM_SIZE)
#define AEON_E_SHIFT		4
#define AEON_EXTENT_SIZE	((1 << AEON_E_SHIFT))
#define AEON_EXTENT_HEADER_SIZE 32
#define AEON_EXTENT_PER_PAGE	(AEON_DEF_BLOCK_SIZE_4K / AEON_EXTENT_SIZE)

#define AEON_ROOT_INO		(1)

/*
 * The first block contains super blocks;
 * The second block contains reserved inodes.
 */
#define	RESERVED_BLOCKS	1

/* AEON supported data blocks */
#define AEON_BLOCK_TYPE_4K     0


#include <linux/uaccess.h>
#include "aeon_tree.h"
struct aeon_region_table {
	spinlock_t r_lock;

	struct tt_root block_free_tree;

	u64	pmem_pool_addr;

	__le64 freed;
	__le32 i_num_allocated_pages;
	__le32 i_range_high;
	__le32 b_range_low;
	__le64 allocated;	/* allocated entire inodes */
	__le16 i_allocated;	/* allocated inodes in current pages */
	__le32 i_head_ino;
	__le64 i_blocknr;	/* it can be deleted */
	__le64 this_block;	/* this table blocknr */

	__le64 num_free_blocks;
	__le64 alloc_data_count;
	__le64 alloc_data_pages;
	__le64 freed_data_count;
	__le64 freed_data_pages;
} __attribute((__packed__));

struct aeon_super_block {
	spinlock_t s_lock;

	__le16 s_map_id;	   /* for allocating inodes in round-robin order */
	__le16 s_cpus;		   /* number of cpus */
	__le32 s_magic;            /* magic signature */
	__le32 s_blocksize;        /* blocksize in bytes */
	__le64 s_size;             /* total size of fs in bytes */
	__le64 s_start_dynamic;

	__le32 s_mtime;            /* mount time */
	__le32 s_wtime;            /* write time */

	__le64 s_num_inodes;
	__le64 s_num_free_blocks;

	char   pad[452];
	__le32 s_csum;              /* checksum of this sb */
} __attribute((__packed__));

struct aeon_dentry {
	u8	name_len;		/* length of the dentry name */
	u8	valid;			/* Invalid now? */
	u8	persisted;		/* fully persisted? */

	__le32	ino;			/* inode no pointed to by this entry */
	__le64	d_pinode_addr;
	__le64	d_inode_addr;
	__le64	d_dentry_addr;

	/* 128 bytes */
	char	name[AEON_NAME_LEN+1];  /* File name */
	/* padding */
	char	pad[92];
	__le32	csum;			/* entry checksum */
} __attribute((__packed__));

#endif
