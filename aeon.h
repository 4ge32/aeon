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

enum node_type {
	NODE_BLOCK = 1,
	NODE_INODE,
	NODE_DIR,
};

struct free_list {
	spinlock_t s_lock;
	struct rb_root	block_free_tree;
	struct aeon_range_node *first_node; // lowest address free range
	struct aeon_range_node *last_node; // highest address free range

	int		index; // Which CPU do I belong to?

	/* Where are the data checksum blocks */
	unsigned long	csum_start;
	unsigned long	replica_csum_start;
	unsigned long	num_csum_blocks;

	/* Where are the data parity blocks */
	unsigned long	parity_start;
	unsigned long	replica_parity_start;
	unsigned long	num_parity_blocks;

	/* Start and end of allocatable range, inclusive. Excludes csum and
	 * parity blocks.
	 */
	unsigned long	block_start;
	unsigned long	block_end;

	unsigned long	num_free_blocks;

	/* How many nodes in the rb tree? */
	unsigned long	num_blocknode;

	u32		csum;		/* Protect integrity */

	/* Statistics */
	unsigned long	alloc_data_count;
	unsigned long	free_data_count;
	unsigned long	alloc_data_pages;
	unsigned long	freed_data_pages;

	u64		padding[8];	/* Cache line break */
};

enum aeon_new_inode_type {
	TYPE_CREATE = 0,
	TYPE_MKNOD,
	TYPE_SYMLINK,
	TYPE_MKDIR
};

struct aeon_inode_info_header {
	/* Map from file offsets to write log entries. */
	struct radix_tree_root tree;
	struct rb_root rb_tree;		/* RB tree for directory */
	struct rb_root vma_tree;	/* Write vmas */
	struct list_head list;		/* SB list of mmap sih */
	int num_vmas;
	unsigned short i_mode;		/* Dir or file? */
	unsigned int i_flags;
	unsigned long i_size;
	unsigned long i_blocks;
	unsigned long ino;
	unsigned long pi_addr;
	unsigned long alter_pi_addr;
	unsigned long valid_entries;	/* For thorough GC */
	unsigned long num_entries;	/* For thorough GC */
	u64 last_setattr;		/* Last setattr entry */
	u64 last_link_change;		/* Last link change entry */
	u64 last_dentry;		/* Last updated dentry */
	u8  i_blk_type;
	struct aeon_inode *pi;
};

struct aeon_inode_info {
	struct aeon_inode_info_header header;
	struct inode vfs_inode;
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

/*
 * Get the persistent memory's address
 */
static inline struct aeon_super_block *aeon_get_super(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return (struct aeon_super_block *)sbi->virt_addr;
}

/* Translate an offset the beginning of the aeon instance to a PMEM address.
 *
 * If this is part of a read-modify-write of the block,
 * aeon_memunlock_block() before calling!
 */
static inline void *aeon_get_block(struct super_block *sb, u64 block)
{
	struct aeon_super_block *ps = aeon_get_super(sb);

	return block ? ((void *)ps + block) : NULL;
}

static inline int aeon_get_reference(struct super_block *sb, u64 block,
		void *dram, void **nvmm, size_t size)
{
	int rc = 0;

	*nvmm = aeon_get_block(sb, block);
	aeon_dbg("%s: nvmm 0x%lx\n", __func__, (unsigned long)*nvmm);
	rc = memcpy_mcsafe(dram, *nvmm, size);
	return rc;
}

static inline struct free_list *aeon_get_free_list(struct super_block *sb, int cpu)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return &sbi->free_lists[cpu];
}

static inline struct aeon_inode_info *AEON_I(struct inode *inode)
{
	return container_of(inode, struct aeon_inode_info, vfs_inode);
}

static inline u64 aeon_get_addr_off(struct aeon_sb_info *sbi) {
	return (u64)sbi->virt_addr;
}

static inline u64 aeon_get_reserved_inode_addr(struct super_block *sb, u64 inode_number)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return aeon_get_addr_off(sbi) + AEON_SB_SIZE
		+ (inode_number % 32 - 1) * AEON_INODE_SIZE;
}

static inline struct aeon_inode *aeon_get_reserved_inode(struct super_block *sb, u64 inode_number)
{
	u64 addr;

	addr = aeon_get_reserved_inode_addr(sb, inode_number);
	aeon_dbg("%s : 0x%lx\n", __func__, (unsigned long)addr);

	return (struct aeon_inode *)addr;
}

static inline struct aeon_inode *aeon_get_inode_by_ino(struct super_block *sb, u64 ino)
{
	if (ino == 0)
		return NULL;
	return aeon_get_reserved_inode(sb, ino);
}

static inline struct aeon_inode *aeon_get_inode(struct super_block *sb, struct inode *inode)
{
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode fake_pi;
	void *addr;
	int rc;

	addr = (void *)sih->pi_addr;
	rc = memcpy_mcsafe(&fake_pi, addr, sizeof(struct aeon_inode));
	if (rc) {
		aeon_err(sb, "%s: ERROR\n", __func__);
		return NULL;
	}

	return (struct aeon_inode *)addr;
}

static inline void aeon_init_header(struct super_block *sb, struct aeon_inode_info_header *sih, u16 i_mode)
{
	sih->i_size = 0;
	sih->ino = 0;
	sih->i_blocks = 0;
	sih->pi_addr = 0;
	sih->alter_pi_addr = 0;
	INIT_RADIX_TREE(&sih->tree, GFP_ATOMIC);
	sih->rb_tree = RB_ROOT;
	sih->vma_tree = RB_ROOT;
	sih->num_vmas = 0;
	INIT_LIST_HEAD(&sih->list);
	sih->i_mode = i_mode;
	sih->i_flags = 0;
	sih->valid_entries = 0;
	sih->num_entries = 0;
	sih->last_setattr = 0;
	sih->last_link_change = 0;
	sih->last_dentry = 0;
}

/* mprotect.c */
extern int aeon_writeable(void *, unsigned long size, int rw);

static inline int aeon_range_check(struct super_block *sb, void *p,
					 unsigned long len)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	if (p < sbi->virt_addr ||
			p + len > sbi->virt_addr + sbi->initsize) {
		aeon_err(sb, "access pmem out of range: pmem range 0x%lx - 0x%lx, "
				"access range 0x%lx - 0x%lx\n",
				(unsigned long)sbi->virt_addr,
				(unsigned long)(sbi->virt_addr + sbi->initsize),
				(unsigned long)p, (unsigned long)(p + len));
		dump_stack();
		return -EINVAL;
	}

	return 0;
}

static inline void
__aeon_memunlock_range(void *p, unsigned long len)
{
	aeon_writeable(p, len, 1);
}

static inline void __aeon_memlock_range(void *p, unsigned long len)
{
	aeon_writeable(p, len, 0);
}

static inline int aeon_is_protected(struct super_block *sb)
{
	struct aeon_sb_info *sbi = (struct aeon_sb_info *)sb->s_fs_info;

	if (wprotect)
		return wprotect;

	return sbi->s_mount_opt & AEON_MOUNT_PROTECT;
}

static inline void aeon_memlock_inode(struct super_block *sb,
				       struct aeon_inode *pi)
{
	if (aeon_is_protected(sb))
		__aeon_memlock_range(pi, AEON_INODE_SIZE);
}

static inline void aeon_memunlock_inode(struct super_block *sb,
					 struct aeon_inode *pi)
{
	if (aeon_range_check(sb, pi, AEON_INODE_SIZE))
		return;

	if (aeon_is_protected(sb))
		__aeon_memunlock_range(pi, AEON_INODE_SIZE);
}


static inline void aeon_memlock_super(struct super_block *sb)
{
	struct aeon_super_block *ps = aeon_get_super(sb);

	if (aeon_is_protected(sb))
		__aeon_memlock_range(ps, AEON_SB_SIZE);
}

static inline void aeon_memunlock_super(struct super_block *sb)
{
	struct aeon_super_block *ps = aeon_get_super(sb);

	if (aeon_is_protected(sb))
		__aeon_memunlock_range(ps, AEON_SB_SIZE);
}

/* operations */
extern const struct inode_operations aeon_dir_inode_operations;
extern const struct inode_operations aeon_dir_inode_operations;
extern const struct file_operations aeon_dax_file_operations;
extern const struct iomap_ops aeon_iomap_ops;
extern const struct file_operations aeon_dir_operations;
extern const struct address_space_operations aeon_aops_dax;

/* super.c */
struct aeon_range_node *aeon_alloc_inode_node(struct super_block *);
void aeon_free_inode_node(struct aeon_range_node *node);
struct aeon_range_node *aeon_alloc_dir_node(struct super_block *sb);
void aeon_free_dir_node(struct aeon_range_node *node);
struct aeon_range_node *aeon_alloc_block_node(struct super_block *sb);
void aeon_free_block_node(struct aeon_range_node *node);

/* balloc.h */
int aeon_alloc_block_free_lists(struct super_block *sb);
void aeon_delete_free_lists(struct super_block *sb);
void aeon_init_blockmap(struct super_block *sb);
int aeon_insert_range_node(struct rb_root *tree, struct aeon_range_node *new_node, enum node_type);
int aeon_find_range_node(struct rb_root *tree, unsigned long key,
	enum node_type type, struct aeon_range_node **ret_node);
int aeon_dax_get_blocks(struct inode *inode, sector_t iblock,
	unsigned long max_blocks, u32 *bno, bool *new, bool *boundary, int create);
int aeon_get_new_inode_block(struct super_block *sb, u64 *pi_addr, int cpuid);
u64 aeon_get_new_dentry_block(struct super_block *sb, u64 *pi_addr, int cpuid);

/* inode.c */
int aeon_init_inode_inuse_list(struct super_block *);
int aeon_get_inode_address(struct aeon_inode_info_header *, u64 ino, u64 *pi_addr);
ino_t aeon_inode_by_name(struct inode *dir, struct qstr *entry);
struct inode *aeon_new_vfs_inode(enum aeon_new_inode_type type,
	struct inode *dir, u64 pi_addr, u64 ino, umode_t mode,
	size_t size, dev_t rdev, const struct qstr *qstr);
u64 aeon_new_aeon_inode(struct super_block *, u64 *);
struct inode *aeon_iget(struct super_block *, unsigned long);

/* dir.c */
int aeon_add_dentry(struct dentry *dentry, u64 ino, int inc_link);
int aeon_remove_dentry(struct dentry *dentry, int dec_link, struct aeon_inode *update);
struct aeon_dentry *aeon_find_dentry(struct super_block *sb,
	struct aeon_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len);
#endif
