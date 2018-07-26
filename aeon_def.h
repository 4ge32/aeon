#ifndef _LINUX_AEON_FS_H
#define _LINUX_AEON_FS_H

#include <linux/types.h>
#include <linux/magic.h>

#define AEON_MAGIC 0xEFF10

#define AEON_INODE_SIZE         128
#define AEON_SB_SIZE            512
#define AEON_DEF_BLOCK_SIZE_4K  4096
#define AEON_NAME_LEN 		128

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
	__le64	aeon_ino;	 /* aeon inode number */

	__le64	next_inode_block;
	__le64  num_pages;

	/* last 40 bytes */
	__le64	dentry_map_block;
	__le64  i_block;        /* point extent_header */

	__le64	i_blocks;       /* point extent log */
	__le64	block;

	struct {
		__le32 rdev;	 /* major/minor # */
	} dev;			 /* device inode */

	__le32	csum;            /* CRC32 checksum */

	/* last 8 bytes */
	__le64  used;            /* used inodes in block */
} __attribute((__packed__));

struct aeon_super_block {
	/* static fields. they never change after file system creation.
	 * checksum only validates up to s_start_dynamic field below */
	__le16		s_sum;              /* checksum of this sb */
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

#define MAX_ENTRY 510
/* TODO
 * scale a number of dentries in the future
 */
struct aeon_dentry_map {
	__le64  block_dentry[MAX_ENTRY];
	__le64  next_map;
	__le64  num_dentries;
}__attribute((__packed__));

struct aeon_dentry {
	/* 8 bytes */
	u8	entry_type;
	u8	name_len;		/* length of the dentry name */
	u8	invalid;		/* Invalid now? */
	u8      pad0;
	/* 8 bytes */
	__le16	de_len;			/* length of this dentry */
	__le16	links_count;
	__le32	mtime;			/* For both mtime and ctime */
	/* 8 bytes */
	__le32	csum;			/* entry checksum */
	__le32  pad1;
	/*  8 bytes */
	__le64	ino;			/* inode no pointed to by this entry */
	/* 128 bytes */
	char	name[AEON_NAME_LEN];	/* File name */
	/* 96 bytes */
	char    pad2[96];
} __attribute((__packed__));

/*
 * extent tree's header referred from inode
 */
struct aeon_extent_header {
	__le16  eh_entries;
	__le16  eh_max;
	__le16  eh_depth;
	__le64  eh_curr_block;
} __attribute((__packed__));

struct aeon_extent {
	__le64  ex_block;
	__le16  ex_length;
	__le64  next_block;
} __attribute((__packed__));

#endif
