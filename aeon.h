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
#define aeon_err(sb, s, args ...)       aeon_err_msg(sb, s, ## args)
#define aeon_warn(s, args ...)          pr_warning(s, ## args)
#define aeon_info(s, args ...)          pr_info(s, ## args)
extern unsigned int aeon_dbgmask;
#define AEON_DBGMASK_VERBOSE	(0x00000010)
#define aeon_dbg_verbose(s, args ...)		 \
	((aeon_dbgmask & AEON_DBGMASK_VERBOSE) ? aeon_dbg(s, ##args) : 0)
#define aeon_dbgv(s, args ...) aeon_dbg_verbose(s, ##args)

#define set_opt(o, opt)		(o |= AEON_MOUNT_ ## opt)

#define	READDIR_END		(ULONG_MAX)
#define	ANY_CPU			(65536)

extern int wprotect;

struct imem_cache {
	u32	ino;
	u64	addr;
	int	independent;
	struct	imem_cache *head;
	struct	list_head imem_list;
};

/*
 * Use it when moount without init option
 */
struct i_valid_list {
	u32	ino;
	u64	addr;
	struct	list_head i_valid_list;
};

struct inode_map {
	struct mutex		inode_table_mutex;
	struct rb_root		inode_inuse_tree;
	unsigned long		num_range_node_inode;
	struct aeon_range_node	*first_inode_range;
	struct imem_cache	*im;
	struct i_valid_list	*ivl;
	u64			curr_i_blocknr;
	void			*virt_addr;
	void			*i_table_addr;
	void			*i_block_addr;
	u32			head_ino;
};

/*
 * AEON super-block data in memory
 */
struct aeon_sb_info {
	struct super_block	*sb;
	struct aeon_super_block *aeon_sb;
	struct block_device	*s_bdev;
	struct dax_device	*s_dax_dev;

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

	struct mutex	s_lock;	/* protects the SB's buffer-head */

	int cpus;
	int trees;
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

	struct aeon_stat_info *stat_info;
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
	struct aeon_dentry_info *de_info;
	struct rb_root rb_tree;		/* RB tree for directory */
	struct rw_semaphore i_mmap_sem;
	int num_vmas;
	u64 pi_addr;
	u64 last_setattr;		/* Last setattr entry */
	u8  i_blk_type;
};

struct aeon_inode_info {
	struct aeon_inode_info_header header;
	struct inode vfs_inode;
};

struct aeon_dentry_invalid {
	struct list_head invalid_list;
	unsigned int	internal;
	unsigned long global;
};

struct aeon_dentry_entry {
	u64 addr;
	ino_t ino;
	struct list_head dmem_cache;
};

struct aeon_dentry_info {
	struct mutex dentry_mutex;

	unsigned int internal;
	unsigned long global;
	struct aeon_dentry_invalid *di;
	struct aeon_dentry *de;
	struct aeon_dentry_map *de_map;
};

static inline int memcpy_to_pmem_nocache(void *dst, const void *src,
					 unsigned int size)
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

static inline u64 aeon_get_block_off(struct super_block *sb,
				     unsigned long blocknr,
				     unsigned short btype)
{
	return (u64)blocknr << AEON_SHIFT;
}

static inline struct free_list *aeon_get_free_list(struct super_block *sb,
						   int cpu)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return &sbi->free_lists[cpu];
}

static inline struct aeon_inode_info *AEON_I(struct inode *inode)
{
	return container_of(inode, struct aeon_inode_info, vfs_inode);
}

static inline struct aeon_region_table *AEON_R_TABLE(struct inode_map *inode_map)
{
	return (struct aeon_region_table *)(inode_map->i_table_addr);
}

static inline u64 aeon_get_addr_off(struct aeon_sb_info *sbi) {
	return (u64)sbi->virt_addr;
}

static inline u64 _aeon_get_reserved_inode_addr(struct super_block *sb,
						u64 inode_number)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return aeon_get_addr_off(sbi) + AEON_SB_SIZE
		+ (inode_number % 32 - 1) * AEON_INODE_SIZE;
}

static inline struct aeon_inode *aeon_get_reserved_inode(struct super_block *sb,
							 u64 inode_number)
{
	u64 addr;

	addr = _aeon_get_reserved_inode_addr(sb, inode_number);

	return (struct aeon_inode *)addr;
}

static inline struct aeon_inode *aeon_get_inode_by_ino(struct super_block *sb,
						       u64 ino)
{
	if (ino == 0)
		return NULL;
	return aeon_get_reserved_inode(sb, ino);
}

static inline
struct aeon_inode *aeon_get_inode(struct super_block *sb,
				  struct aeon_inode_info_header *sih)
{
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

static inline
struct aeon_dentry_map *aeon_get_first_dentry_map(struct super_block *sb,
						  struct aeon_inode *pi)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long blocknr = le64_to_cpu(pi->dentry_map_block);
	struct aeon_dentry_map *de_map;

	if (blocknr == 0)
		return NULL;

	de_map = (struct aeon_dentry_map *)(sbi->virt_addr
					    + (blocknr << AEON_SHIFT));
	if (le64_to_cpu(de_map->num_dentries) == 2)
		return NULL;

	return de_map;

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

static inline
struct aeon_extent_header *AEON_EXTENT_HEADER(struct super_block *sb,
					      struct aeon_inode *pi)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long addr;

	addr = (u64)sbi->virt_addr + (pi->i_block << 12);
	return (struct aeon_extent_header *)addr;
}

static inline struct aeon_extent *AEON_EXTENT(struct super_block *sb,
					      struct aeon_inode *pi)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long addr;

	addr = (u64)sbi->virt_addr + (pi->i_blocks << 12);
	return (struct aeon_extent *)addr;
}

/* operations */
extern const struct inode_operations aeon_dir_inode_operations;
extern const struct inode_operations aeon_dir_inode_operations;
extern const struct inode_operations aeon_file_inode_operations;
extern const struct inode_operations aeon_symlink_inode_operations;
extern const struct file_operations aeon_dax_file_operations;
extern const struct file_operations aeon_dir_operations;
extern const struct iomap_ops aeon_iomap_ops;
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
unsigned long aeon_count_free_blocks(struct super_block *sb);
void aeon_init_blockmap(struct super_block *sb);
int aeon_insert_range_node(struct rb_root *tree,
			   struct aeon_range_node *new_node, enum node_type);
int aeon_find_range_node(struct rb_root *tree, unsigned long key,
			 enum node_type type, struct aeon_range_node **ret_node);
void aeon_destroy_range_node_tree(struct super_block *sb, struct rb_root *tree);
int aeon_new_data_blocks(struct super_block *sb,
	struct aeon_inode_info_header *sih, unsigned long *blocknr,
	unsigned long start_blk, unsigned int num, int cpu);
int aeon_dax_get_blocks(struct inode *inode, sector_t iblock,
			unsigned long max_blocks, u32 *bno, bool *new,
			bool *boundary, int create);
u64 aeon_get_new_inode_block(struct super_block *sb, int cpuid, u32 start_ino);
void aeon_init_new_inode_block(struct super_block *sb, int cpu_id, u32 ino);
unsigned long aeon_get_new_dentry_block(struct super_block *sb,
					u64 *pi_addr, int cpuid);
unsigned long aeon_get_new_dentry_map_block(struct super_block *sb,
					    u64 *pi_addr, int cpuid);
unsigned long aeon_get_new_symlink_block(struct super_block *sb,
					 u64 *pi_addr, int cpuid);

/* inode.c */
int aeon_init_inode_inuse_list(struct super_block *sb);
int aeon_get_inode_address(struct super_block *sb,
			   u32 ino, u64 *pi_addr, struct aeon_dentry *de);
u32 aeon_inode_by_name(struct inode *dir, struct qstr *entry);
struct inode *aeon_new_vfs_inode(enum aeon_new_inode_type type,
				 struct inode *dir, u64 pi_addr, u32 ino,
				 umode_t mode, size_t size, dev_t rdev,
				 const struct qstr *qstr);
u32 aeon_new_aeon_inode(struct super_block *sb, u64 *pi_addr, u64 *i_blocknr);
struct inode *aeon_iget(struct super_block *sb, u32 ino);
int aeon_free_inode_resource(struct super_block *sb, struct aeon_inode *pi,
			     struct aeon_inode_info_header *sih);
int aeon_free_dram_resource(struct super_block *sb,
			    struct aeon_inode_info_header *sih);
int aeon_setattr(struct dentry *dentry, struct iattr *iattr);

/* dir.c */
int aeon_insert_dir_tree(struct super_block *sb,
			 struct aeon_inode_info_header *sih,
			 const char *name, int namelen,
			 struct aeon_dentry *direntry);
int aeon_add_dentry(struct dentry *dentry, u32 ino,
		    u64 i_blocknr, int inc_link);
int aeon_remove_dentry(struct dentry *dentry, int dec_link,
		       struct aeon_inode *update, struct aeon_dentry *de);
struct aeon_dentry *aeon_find_dentry(struct super_block *sb,
				     struct aeon_inode *pi,
				     struct inode *inode, const char *name,
				     unsigned long name_len);
void aeon_delete_dir_tree(struct super_block *sb,
			  struct aeon_inode_info_header *sih);
struct aeon_dentry *aeon_dotdot(struct super_block *sb,
				struct aeon_inode_info_header *sih);
void aeon_set_link(struct inode *dir, struct aeon_dentry *de,
		   struct inode *inode, int update_times);
int aeon_empty_dir(struct inode *inode);
void aeon_free_invalid_dentry_list(struct super_block *sb,
				   struct aeon_inode_info_header *sih);

/* rebuild.c */
int aeon_rebuild_dir_inode_tree(struct super_block *sb, struct aeon_inode *pi,
				u64 pi_addr, struct aeon_inode_info_header *sih);
void aeon_rebuild_inode_cache(struct super_block *sb, int cpu);

/* symlink.c */
int aeon_block_symlink(struct super_block *sb, struct aeon_inode *pi,
		       const char *symname, int len);

/* debug.c */
int aeon_build_stats(struct aeon_sb_info *sbi);
void aeon_destroy_stats(struct aeon_sb_info *sbi);
int __init aeon_create_root_stats(void);
void aeon_destroy_root_stats(void);

#endif
