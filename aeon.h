#ifndef __AEON_H
#define __AEON_H

#include "aeon_def.h"
#include <linux/uaccess.h>
#include <linux/fs.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

/* #define aeon_dbg(s, args...)         pr_debug(s, ## args) */
extern void aeon_err_msg(struct super_block *sb, const char *fmt, ...);
#define aeon_dbg(s, args ...)           pr_info(s, ## args)
#define aeon_dbg1(s, args ...)
#define aeon_err(sb, s, args ...)       aeon_err_msg(sb, s, ## args)
#define aeon_warn(s, args ...)          pr_warning(s, ## args)
#define aeon_info(s, args ...)          pr_info(s, ## args)

#define set_opt(o, opt)		(o |= AEON_MOUNT_ ## opt)

#define	READDIR_END		(ULONG_MAX)
#define	ANY_CPU			(65536)

extern int wprotect;

struct inode_map {
	struct mutex inode_table_mutex;
	struct rb_root	inode_inuse_tree;
	unsigned long	num_range_node_inode;
	struct aeon_range_node *first_inode_range;
	void *virt_addr;
	int allocated;
	int freed;
};

/*
 * AEON super-block data in memory
 */
struct aeon_sb_info {
	struct super_block *sb;
	struct aeon_super_block *aeon_sb;
	struct block_device *s_bdev;
	struct dax_device *s_dax_dev;

	/*
	 * base physical and virtual address of AEON (which is also
	 * the pointer to the super block)
	 */
	phys_addr_t	phys_addr;
	void		*virt_addr;

	unsigned long	num_blocks;

	/*
	 * Backing store option:
	 * 1 = no load, 2 = no store,
	 * else do both
	 */
	unsigned int	aeon_backing_option;

	/* Mount options */
	unsigned long	bpi;
	unsigned long	num_inodes;
	unsigned long	blocksize;
	unsigned long	initsize;
	unsigned long	s_mount_opt;
	kuid_t		uid;    /* Mount uid for root directory */
	kgid_t		gid;    /* Mount gid for root directory */
	umode_t		mode;   /* Mount mode for root directory */
	atomic_t	next_generation;
	/* inode tracking */
	unsigned long	s_inodes_used_count;
	unsigned long	reserved_blocks;

	struct mutex 	s_lock;	/* protects the SB's buffer-head */

	int cpus;
	//struct proc_dir_entry *s_proc;

	/* ZEROED page for cache page initialized */
	//void *zeroed_page;

	/* Per-CPU inode map */
	struct inode_map	*inode_maps;

	/* Decide new inode map id */
	unsigned long map_id;

	/* Per-CPU free block list */
	struct free_list *free_lists;

	/* Shared free block list */
	unsigned long per_list_blocks;
	//struct free_list shared_free_list;

	int max_inodes_in_page;
};

struct aeon_range_node {
	struct rb_node node;
	struct vm_area_struct *vma;
	unsigned long mmap_entry;
	union {
		struct {
			unsigned long range_low;
			unsigned long range_high;
		};
		struct {
			unsigned long hash;
			void *direntry;
		};
	};
	u32 csum;
};

static inline int memcpy_to_pmem_nocache(void *dst, const void *src, unsigned int size)
{
	int ret;

	ret = __copy_from_user_inatomic_nocache(dst, src, size);

	return ret;
}

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

static inline unsigned long
aeon_get_numblocks(unsigned short btype)
{
	unsigned long num_blocks;

	num_blocks = 1;

	return num_blocks;
}

static inline struct aeon_sb_info *AEON_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline int aeon_get_cpuid(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return smp_processor_id() % sbi->cpus;
}

/* operations */
extern const struct inode_operations aeon_dir_inode_operations;
extern const struct inode_operations aeon_dir_inode_operations;
extern const struct file_operations aeon_dax_file_operations;
extern const struct iomap_ops aeon_iomap_ops;
extern const struct file_operations aeon_dir_operations;
#endif
