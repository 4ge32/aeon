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
#define AEON_INTERNAL_ENTRY     (AEON_D_SHIFT * AEON_PAGES_FOR_DENTRY)
#define MAX_ENTRY               507
#define MAX_DENTRY ((MAX_ENTRY << AEON_D_SHIFT ) + \
		   ((MAX_ENTRY - 1 ) << AEON_D_SHIFT))
#define AEON_DENTRY_MAP_SIZE	AEON_DEF_BLOCK_SIZE_4K
#define AEON_DENTRY_MAP_CSIZE	(AEON_DENTRY_MAP_SIZE - CHECKSUM_SIZE)
#define AEON_E_SHIFT		4
#define AEON_EXTENT_SIZE	((1 << AEON_E_SHIFT))
#define AEON_EXTENT_HEADER_SIZE 32
#define AEON_EXTENT_PER_PAGE	(AEON_DEF_BLOCK_SIZE_4K / AEON_EXTENT_SIZE)

#define AEON_ROOT_INO		(1)
#define AEON_INODE_START        (4)

/*
 * The first block contains super blocks;
 * The second block contains reserved inodes.
 */
#define	RESERVED_BLOCKS	1

/* AEON supported data blocks */
#define AEON_BLOCK_TYPE_4K     0

/*
 * extent tree's header referred from inode
 */
#define PI_MAX_INTERNAL_EXTENT 5
#define PI_MAX_EXTERNAL_EXTENT 3
struct aeon_extent_header {
	__le16  eh_entries;
	__le16  eh_depth;
	__le64  eh_extent_blocks[PI_MAX_EXTERNAL_EXTENT];
	__le32  eh_blocks;
} __attribute((__packed__));

struct aeon_extent {
	__le16	ex_index;
	__le64  ex_block;
	__le16  ex_length;
	__le32  ex_offset;
} __attribute((__packed__));

/*
 * Structure of an inode in AEON.
 */
struct aeon_inode {
	/* first 40 bytes */
	u8	persisted;	 /* Is this inode persistent? */
	u8	valid;		 /* Is this inode valid? */
	u8	deleted;	 /* Is this inode deleted? */
	u8	i_new;           /* Is this inode new? */
	u8	use_rb;		 /* Is this inode using rb for extent? */
	/* 4  */
	__le32	i_flags;	 /* Inode flags */
	__le64	i_size;		 /* Size of data in bytes */
	__le32	i_ctime;	 /* Inode modification time */
	__le32	i_mtime;	 /* Inode tree Modification time */
	__le32	i_atime;	 /* Access time */
	__le16	i_mode;		 /* File mode */
	__le64	i_links_count;	 /* Links count */

	__le64	i_xattr;	 /* Extended attribute block */

	/* second 40 bytes */
	__le32	i_uid;		 /* Owner Uid */
	__le32	i_gid;		 /* Group Id */
	__le32	i_generation;	 /* File version (for NFS) */
	__le32	i_create_time;	 /* Create time */
	__le32	aeon_ino;	 /* aeon inode number */
	__le32	parent_ino;	 /* parent inode number */

	__le64	i_dentry_block;	/* block that holds a related dentry */
	__le32	i_d_internal;

	__le64  i_inode_blok;	/* inode itself belongs  */

	__le64	i_next_inode_block;
	u8      i_internal_allocated;

	__le64  i_block;        /* exist extent or point extent block */
	__le64	i_blocks;       /* block counts */
	__le64	sym_block;      /* for symbolic link */

	struct {
		__le32 rdev;	 /* major/minor # */
	} dev;			 /* device inode */

	struct aeon_extent_header aeh;
	struct aeon_extent ae[PI_MAX_INTERNAL_EXTENT];
	__le16 i_exblocks;

	char	pad[10];
	__le32	csum;            /* CRC32 checksum */
} __attribute((__packed__));

struct aeon_region_table {
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

	char   pad[456];
	__le32 s_csum;              /* checksum of this sb */
} __attribute((__packed__));

struct aeon_dentry {
	u8	name_len;		/* length of the dentry name */
	u8	valid;			/* Invalid now? */
	u8	persisted;		/* fully persisted? */
	/* dynamic variable */
	__le32  internal_offset;
	__le32  global_offset;
	__le32	ino;			/* inode no pointed to by this entry */
	__le64	i_blocknr;		/* block that holds a related inode */
	/* 128 bytes */
	char	name[AEON_NAME_LEN];	/* File name */
	/* padding */
	char	pad[101];
	__le32	csum;			/* entry checksum */
} __attribute((__packed__));

#endif
