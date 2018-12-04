#ifndef _LINUX_AEON_FS_H
#define _LINUX_AEON_FS_H

#include <linux/types.h>
#include <linux/magic.h>

#define AEON_MAGIC		0xEFF10

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

#endif
