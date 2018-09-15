#ifndef _LINUX_AEON_FS_H
#define _LINUX_AEON_FS_H

#include <linux/types.h>
#include <linux/magic.h>

#define AEON_MAGIC 0xEFF10

/* manual */
#define AEON_I_SHIFT            8
#define AEON_PAGES_FOR_INODE    5
#define AEON_PAGES_FOR_DENTRY   5
#define SEED			131

/* auto */
#define AEON_INODE_SIZE         (1 << AEON_I_SHIFT)
#define AEON_SB_SIZE            512
#define AEON_SHIFT              12
#define AEON_DEF_BLOCK_SIZE_4K  (1 << AEON_SHIFT)
#define AEON_I_NUM_PER_PAGE     ((AEON_DEF_BLOCK_SIZE_4K / AEON_INODE_SIZE) * \
							AEON_PAGES_FOR_INODE)
#define AEON_NAME_LEN		128
#define AEON_DENTRY_SIZE        256
#define AEON_D_SHIFT            8
#define AEON_INTERNAL_ENTRY     (AEON_D_SHIFT * AEON_PAGES_FOR_DENTRY)
#define MAX_ENTRY               508
#define MAX_DENTRY ((MAX_ENTRY << AEON_D_SHIFT ) + \
		   ((MAX_ENTRY - 1 ) << AEON_D_SHIFT))

#define AEON_ROOT_INO		(1)
#define AEON_INODE_START        (4)

/*
 * The first block contains super blocks;
 * The second block contains reserved inodes.
 */
#define	RESERVED_BLOCKS	1

/*
 * Mount flags
 */
#define AEON_MOUNT_PROTECT      0x000001    /* wprotect CR0.WP */
#define AEON_MOUNT_DAX          0x000008    /* Direct Access */
#define AEON_MOUNT_FORMAT       0x000200    /* was FS formatted on mount? */


/* AEON supported data blocks */
#define AEON_BLOCK_TYPE_4K     0

/*
 * extent tree's header referred from inode
 */
#define AEON_EXTENT_HEADER_SIZE 32
struct aeon_extent_header {
	__le16  eh_entries;
	__le16  eh_max;
	__le16  eh_depth;
	__le64  eh_curr_block;
	__le32  eh_iblock;
	__le32  eh_blocks;
} __attribute((__packed__));

#define AEON_EXTENT_SIZE 32
struct aeon_extent {
	__le64  ex_block;
	__le16  ex_length;
	__le64  next_block;
} __attribute((__packed__));

/*
 * Structure of an inode in AEON.
 */
struct aeon_inode {
	/* first 40 bytes */
	u8	i_rsvd;		 /* reserved. used to be checksum */
	u8	valid;		 /* Is this inode valid? */
	u8	deleted;	 /* Is this inode deleted? */
	u8	i_new;           /* Is this inode new? */
	/* 4  */
	__le32	i_flags;	 /* Inode flags */
	__le64	i_size;		 /* Size of data in bytes */
	__le32	i_ctime;	 /* Inode modification time */
	__le32	i_mtime;	 /* Inode b-tree Modification time */
	__le32	i_atime;	 /* Access time */
	__le16	i_mode;		 /* File mode */
	__le16	i_links_count;	 /* Links count */

	__le64	i_xattr;	 /* Extended attribute block */

	/* second 40 bytes */
	__le32	i_uid;		 /* Owner Uid */
	__le32	i_gid;		 /* Group Id */
	__le32	i_generation;	 /* File version (for NFS) */
	__le32	i_create_time;	 /* Create time */
	__le32	aeon_ino;	 /* aeon inode number */

	__le64	i_next_inode_block;
	u8      i_internal_allocated;

	/* last 40 bytes */
	__le64	dentry_map_block;
	__le64  i_block;        /* point extent_header */
	__le64	i_blocks;       /* point extent log */
	__le64	sym_block;      /* for symbolic link */

	struct {
		__le32 rdev;	 /* major/minor # */
	} dev;			 /* device inode */

	struct aeon_extent_header aeh;
	struct aeon_extent ae[4];

	__le32	csum;            /* CRC32 checksum */
	char    pad[4 * 4 + 3];
} __attribute((__packed__));

struct aeon_region_table {
	__le64 allocated;
	__le64 freed;
	__le32 i_num_allocated_pages;
	__le32 i_range_high;
	__le32 b_range_low;
	__le16 i_allocated;
};

struct aeon_super_block {
	/* static fields. they never change after file system creation.
	 * checksum only validates up to s_start_dynamic field below */
	__le32		s_csum;              /* checksum of this sb */
	__le16          s_map_id;
	__le16          s_cpus;
	__le32		s_magic;            /* magic signature */
	__le32		s_blocksize;        /* blocksize in bytes */
	__le64		s_size;             /* total size of fs in bytes */

	__le64		s_start_dynamic;
	__le64          s_num_inodes;

	/* all the dynamic fields should go here */
	/* s_mtime and s_wtime should be together and their order should not be
	 * changed. we use an 8 byte write to update both of them atomically */
	__le32		s_mtime;            /* mount time */
	__le32		s_wtime;            /* write time */
	/* fields for fast mount support. Always keep them together */
	__le64		s_num_free_blocks;
} __attribute((__packed__));

/* TODO
 * scale a number of dentries in the future
 */
struct aeon_dentry_map {
	__le64  block_dentry[MAX_ENTRY];
	__le64  next_map;
	__le64  num_dentries;
	__le64  num_latest_dentry;
	__le64  num_internal_dentries;
}__attribute((__packed__));

struct aeon_dentry {
	/* 8 bytes */
	u8	entry_type;
	u8	name_len;		/* length of the dentry name */
	u8	valid;			/* Invalid now? */
	u8      pad0;
	/* 8 bytes */
	__le16	de_len;			/* length of this dentry */
	__le16	links_count;
	__le32	mtime;			/* For both mtime and ctime */
	/* 8 bytes */
	__le32	csum;			/* entry checksum */
	/* TODO: size of variable */
	__le64  internal_offset;
	__le32  global_offset;
	/*  8 bytes */
	__le32	ino;			/* inode no pointed to by this entry */
	__le64	i_blocknr;		/* related block that holds inode */
	/* 128 bytes */
	char	name[AEON_NAME_LEN];	/* File name */
	/* 96 bytes */
} __attribute((__packed__));

#endif
