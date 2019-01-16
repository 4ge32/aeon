/*
 *
 * BRIEF DESCRIPTION
 *
 * Definitions for the AEON filesystem.
 *
 * Copyright 2018 Fumiya Shigemitsu <shfy1014@gmail.com>
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */
#ifndef __AEON_H
#define __AEON_H

#define AEON_MAGIC		0xEFF10
#define AEON_ROOT_INO		(1)
/*
 * The first block contains super blocks;
 * and reserved inodes.
 */
#define	RESERVED_BLOCKS	1

/* AEON supported data blocks */
#define AEON_BLOCK_TYPE_4K     0

#include <linux/types.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/crc32.h>

/* manual */
#define AEON_I_SHIFT            8
#define AEON_D_SHIFT            8
#define AEON_PAGES_FOR_INODE    1
#define AEON_PAGES_FOR_DENTRY   1
#define SEED			131

/* auto */
#define CHECKSUM_SIZE		4
#define AEON_SHIFT              12
#define AEON_DEF_BLOCK_SIZE_4K  (1 << AEON_SHIFT)

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

extern void aeon_err_msg(struct super_block *sb, const char *fmt, ...);
#define AEON_ERR(msg)			printk(KERN_CRIT "aeon_err:"	\
					       "%s - %d - %d\n",	\
						__func__, __LINE__, msg)
#define aeon_dbg(s, args ...)           pr_info(s, ## args)
#define aeon_err(sb, s, args ...)       aeon_err_msg(sb, s, ## args)
#define aeon_warn(s, args ...)          pr_warning(s, ## args)
#define aeon_info(s, args ...)          pr_info(s, ## args)

#ifdef CONFIG_AEON_FS_DEBUG_MODE
#define aeon_dbgv(s, args ...)		pr_info(s, ## args)
#else
#define aeon_dbgv(s, args ...)		do { } while (0)
#endif

#define	READDIR_END		(ULONG_MAX)
#define	ANY_CPU			(65536)

#define dax_sem_down_write(aeon_inode)	down_write(&(aeon_inode)->dax_sem)
#define dax_sem_up_write(aeon_inode)	up_write(&(aeon_inode)->dax_sem)

/*
 * Mount flags
 */
#define AEON_MOUNT_PROTECT      0x000001    /* wprotect CR0.WP */
#define AEON_MOUNT_DAX          0x000008    /* Direct Access */
#define AEON_MOUNT_FORMAT       0x000200    /* was FS formatted on mount? */
#define AEON_MOUNT_XATTR_USER	0x004000    /* Extended user attributes */

#define set_opt(o, opt)		(o |= AEON_MOUNT_##opt)
#define clear_opt(o, opt)	(o &= ~AEON_MOUNT_##opt)
#define test_opt(sb, opt)	(AEON_SB(sb)->s_mount_opt & \
				 AEON_MOUNT_##opt)
/*
 * ioctl commands
 */
#define	AEON_IOC_GETFLAGS		FS_IOC_GETFLAGS
#define	AEON_IOC_SETFLAGS		FS_IOC_SETFLAGS
#define	AEON_IOC_GETVERSION		FS_IOC_GETVERSION
#define	AEON_IOC_SETVERSION		FS_IOC_SETVERSION
#define AEON_IOC_INODE_ATTACK		_IOWR('f', 5, long)
#define AEON_IOC_DENTRY_ATTACK		_IOWR('f', 6, long)
#define AEON_IOC_CHILD_ID_ATTACK	_IOWR('f', 7, long)
#define AEON_IOC_TEST_LIBAEON		_IOWR('f', 8, long)
#define AEON_IOC_TEST_COMPRESSION	_IOWR('f', 9, long)

/*
 * ioctl commands in 32 bit emulation
 */
#define AEON_IOC32_GETFLAGS		FS_IOC32_GETFLAGS
#define AEON_IOC32_SETFLAGS		FS_IOC32_SETFLAGS
#define AEON_IOC32_GETVERSION		FS_IOC32_GETVERSION
#define AEON_IOC32_SETVERSION		FS_IOC32_SETVERSION

/*
 * ioctl flags
 */
#define AEON_IMMUTABLE_FL		FS_IMMUTABLE_FL	/* Immutable file */
#define AEON_APPEND_FL			FS_APPEND_FL	/* writes to file may only append */
#define AEON_FL_USER_VISIBLE		FS_FL_USER_VISIBLE
#define AEON_FL_USER_MODIFIABLE		FS_FL_USER_MODIFIABLE
#define AEON_TOPDIR_FL			FS_TOPDIR_FL	/* Top of directory hierarchies*/
#define AEON_NODUMP_FL			FS_NODUMP_FL	/* do not dump file */
#define AEON_NOATIME_FL			FS_NOATIME_FL	/* do not update atime */

/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define AEON_REG_FLMASK	~AEON_TOPDIR_FL
/* Flags that are appropriate for non-directories/regular files. */
#define AEON_OTHER_FLMASK (AEON_NODUMP_FL | AEON_NOATIME_FL)

extern int wprotect;

struct aeon_mdata {
	u64 pi_addr;
	u64 de_addr;
	u32 ino;
	umode_t mode;
	struct aeon_inode *pidir;
	size_t size;
	dev_t rdev;
};

struct opaque_list {
	struct aeon_inode *pi;
	struct aeon_dentry *de;
	struct list_head opaque_list;
};

struct inode_map {
	struct mutex		inode_table_mutex;
	struct rb_root		inode_inuse_tree;
	unsigned long		num_range_node_inode;
	struct aeon_range_node	*first_inode_range;
	struct imem_cache	*im;
	void			*i_table_addr;
};

struct aeon_range_node {
	struct rb_node node;
	struct vm_area_struct *vma;
	union {
		struct {
			unsigned long range_low;
			unsigned long range_high;
		};
		struct {
			unsigned long hash;
			struct aeon_dentry *direntry;
		};
		struct {
			unsigned long offset;
			int length;
			struct aeon_extent *extent;
		};
	};
	u32 csum;
};

struct aeon_region_table {
	spinlock_t r_lock;

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

	__le32 i_top_ino;

	__le64 num_free_blocks;
	__le64 alloc_data_count;
	__le64 alloc_data_pages;
	__le64 freed_data_count;
	__le64 freed_data_pages;
} __attribute((__packed__));


#include "aeon_super.h"
#include "aeon_inode.h"
#include "aeon_dir.h"

static inline int memcpy_to_pmem_nocache(void *dst, const void *src,
					 unsigned int size)
{
	int ret;

	ret = __copy_from_user_inatomic_nocache(dst, src, size);

	return ret;
}

static inline struct inode_map *aeon_get_inode_map(struct super_block *sb,
						   int cpu_id)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return &sbi->inode_maps[cpu_id];
}

static inline unsigned int
aeon_get_numblocks(unsigned short btype)
{
	return 1;
}


static inline struct aeon_region_table *AEON_R_TABLE(struct inode_map *inode_map)
{
	return (struct aeon_region_table *)(inode_map->i_table_addr);
}

static inline
struct aeon_region_table *aeon_get_rtable(struct super_block *sb, int cpu_id)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map = &sbi->inode_maps[cpu_id];

	return (struct aeon_region_table *)(inode_map->i_table_addr);
}

/* ======================= Write ordering ========================= */

#define CACHELINE_SIZE  (64)
#define CACHELINE_MASK  (~(CACHELINE_SIZE - 1))
#define CACHELINE_ALIGN(addr) (((addr)+CACHELINE_SIZE-1) & CACHELINE_MASK)

extern int support_clwb;

static inline bool arch_has_clwb(void)
{
	return static_cpu_has(X86_FEATURE_CLWB);
}

#define _mm_clflush(addr)\
	asm volatile("clflush %0" : "+m" (*(volatile char *)(addr)))
#define _mm_clflushopt(addr)\
	asm volatile(".byte 0x66; clflush %0" : "+m" \
		     (*(volatile char *)(addr)))
#define _mm_clwb(addr)\
	asm volatile(".byte 0x66; xsaveopt %0" : "+m" \
		     (*(volatile char *)(addr)))

static inline void PERSISTENT_BARRIER(void)
{
	asm volatile ("sfence\n" : : );
}

static inline void aeon_flush_buffer(void *buf, uint32_t len, bool fence)
{
	uint32_t i;

	len = len + ((unsigned long)(buf) & (CACHELINE_SIZE - 1));
	if (support_clwb) {
		for (i = 0; i < len; i += CACHELINE_SIZE)
			_mm_clwb(buf + i);
	} else {
		for (i = 0; i < len; i += CACHELINE_SIZE)
			_mm_clflush(buf + i);
	}
	/* Do a fence only if asked. We often don't need to do a fence
	 * immediately after clflush because even if we get context switched
	 * between clflush and subsequent fence, the context switch operation
	 * provides implicit fence.
	 */
	if (fence)
		PERSISTENT_BARRIER();
}

static inline void aeon_flush_64bit(void *buf)
{
	aeon_flush_buffer(buf, 64, 1);
}

#include "mprotect.h"

/* operations */
extern const struct inode_operations aeon_dir_inode_operations;
extern const struct inode_operations aeon_dir_inode_operations;
extern const struct inode_operations aeon_file_inode_operations;
extern const struct inode_operations aeon_symlink_inode_operations;
extern const struct inode_operations aeon_special_inode_operations;
extern const struct file_operations aeon_dax_file_operations;
extern const struct file_operations aeon_dir_operations;
extern const struct iomap_ops aeon_iomap_ops;
extern const struct address_space_operations aeon_dax_aops;

/* rebuild.c */
int aeon_rebuild_extenttree(struct super_block *sb,
			    struct aeon_inode *pi, struct inode *inode);
int aeon_rebuild_dir_inode_tree(struct super_block *sb, struct aeon_inode *pi,
				u64 pi_addr, struct inode *inode);
void aeon_rebuild_inode_cache(struct super_block *sb);

/* symlink.c */
int aeon_delete_symblock(struct super_block *sb,
			 struct aeon_inode_info_header *sih);
int aeon_block_symlink(struct super_block *sb, struct aeon_inode *pi,
		       const char *symname, int len);

/* ioctl.c */
long aeon_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
long aeon_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#endif

/* debug.c */
int aeon_build_stats(struct aeon_sb_info *sbi);
void aeon_destroy_stats(struct aeon_sb_info *sbi);
int __init aeon_create_root_stats(void);
void aeon_destroy_root_stats(void);

#endif
