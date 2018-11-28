#ifndef __AEON_H
#define __AEON_H

#include "aeon_def.h"
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/crc32.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

extern void aeon_err_msg(struct super_block *sb, const char *fmt, ...);
/* #define aeon_dbg(s, args...)         pr_debug(s, ## args) */
#define aeon_dbg(s, args ...)           pr_info(s, ## args)
#define aeon_err(sb, s, args ...)       aeon_err_msg(sb, s, ## args)
#define aeon_warn(s, args ...)          pr_warning(s, ## args)
#define aeon_info(s, args ...)          pr_info(s, ## args)

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

/* rb tree for extent is experimetal */
#define USE_RB

extern int wprotect;

struct imem_cache {
	u32	ino;
	u64	addr;
	int	independent;
	struct	imem_cache *head;
	struct	list_head imem_list;
};

struct i_valid_list {
	u32	parent_ino;
	u64	addr;
	struct	i_valid_child_list *ivcl;
	struct	list_head i_valid_list;
};

struct i_valid_child_list {
	u32	ino;
	u64	addr;
	u32	parent_ino;
	struct	list_head i_valid_child_list;
};

struct obj_queue {
	struct aeon_inode *pi;
	struct aeon_dentry *de;
	struct list_head obj_queue;
};

struct inode_map {
	struct mutex		inode_table_mutex;
	struct rb_root		inode_inuse_tree;
	unsigned long		num_range_node_inode;
	struct aeon_range_node	*first_inode_range;
	struct imem_cache	*im;
	void			*i_table_addr;
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
	unsigned long	last_addr;

	/* Mount options */
	unsigned long	blocksize;
	unsigned long	initsize;
	unsigned long	s_mount_opt;
	kuid_t		uid;		/* Mount uid for root directory */
	kgid_t		gid;		/* Mount gid for root directory */
	umode_t		mode;		/* Mount mode for root directory */
	atomic_t	next_generation;

	/* protects the SB's buffer-head */
	struct mutex s_lock;

	/* the number of cpu cores */
	int cpus;

	/* per-CPU inode map */
	struct inode_map *inode_maps;

	/* per CPU free block list */
	struct free_list *free_lists;

	/* shared free block list */
	unsigned long per_list_blocks;

	/* used in mount time */
	struct i_valid_list *ivl;

	/* store root inode info */
	struct aeon_inode_info *si;

	/* used show debug info */
	struct aeon_stat_info *stat_info;

	/* used in recovery process */
	struct obj_queue *oq;
	struct obj_queue *spare_oq;

	struct mb_cache *s_ea_block_cache;
};

struct aeon_range_node {
	struct rb_node node;
	struct tt_node tt_node;
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

enum node_type {
	NODE_BLOCK = 1,
	NODE_INODE,
	NODE_DIR,
	NODE_EXTENT,
};

struct free_list {
	spinlock_t s_lock;
	struct rb_root	block_free_tree;
	struct aeon_range_node *first_node; // lowest address free range
	struct aeon_range_node *last_node; // highest address free range

	int		index; // Which CPU do I belong to?

	unsigned long	block_start;
	unsigned long	block_end;

	unsigned long	num_free_blocks;

	/* How many nodes in the rb tree? */
	unsigned long	num_blocknode;

	u32		csum;		/* Protect integrity */
};

#include "aeon_inode.h"

struct aeon_inode_info {
	struct aeon_inode_info_header header;
	struct inode vfs_inode;
};

struct aeon_dentry_invalid {
	struct list_head invalid_list;
	u64 d_addr;
};

struct aeon_dentry_map {
	unsigned long  block_dentry[MAX_ENTRY];
	unsigned long  next_map;
	unsigned long  num_dentries;
	unsigned int  num_latest_dentry;
	unsigned int  num_internal_dentries;
};

struct aeon_dentry_info {
	struct mutex dentry_mutex;
	struct aeon_dentry_invalid *di;
	struct aeon_dentry_map de_map;
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

static inline unsigned int
aeon_get_numblocks(unsigned short btype)
{
	return 1;
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

static inline
struct aeon_region_table *aeon_get_rtable(struct super_block *sb, int cpu_id)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map = &sbi->inode_maps[cpu_id];

	return (struct aeon_region_table *)(inode_map->i_table_addr);
}

static inline u64 aeon_get_addr_off(struct aeon_sb_info *sbi) {
	return (u64)sbi->virt_addr;
}

static inline
u64 aeon_get_reserved_inode_addr(struct super_block *sb, u64 inode_number)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return aeon_get_addr_off(sbi) + AEON_SB_SIZE +
		(inode_number % 32 - 1) * AEON_INODE_SIZE;
}

static inline
struct aeon_inode *aeon_get_reserved_inode(struct super_block *sb, u64 ino)
{
	return (struct aeon_inode *)aeon_get_reserved_inode_addr(sb, ino);
}

static inline
struct aeon_inode *aeon_get_reserved_inode_ino(struct super_block *sb, u64 ino)
{
	if (ino == 0)
		return NULL;
	return (struct aeon_inode *)aeon_get_reserved_inode_addr(sb, ino);
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

/*
 * This function only is called from ioctl.c for the purpose of
 * file system test so far.
 */
static inline
struct aeon_inode *aeon_get_parent_inode(struct super_block *sb,
					 struct aeon_inode_info_header *sih)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode *pi;
	u64 addr;

	pi = aeon_get_inode(sb, sih);
	addr = (u64)sbi->virt_addr + le64_to_cpu(pi->i_pinode_addr);

	return (struct aeon_inode *)addr;
}

static inline
struct aeon_dentry_map *aeon_get_dentry_map(struct super_block *sb,
					    struct aeon_inode_info_header *sih)
{
	if (!sih->de_info)
		return NULL;

	return &sih->de_info->de_map;

}

/* checksum */
#define VALID	1
#define INVALID 0

static inline int is_persisted_dentry(struct aeon_dentry *de)
{
	__le32 temp;

	temp = cpu_to_le32(crc32_le(SEED,
				    (unsigned char *)de,
				    AEON_DENTRY_CSIZE));
	if (temp != de->csum)
		return INVALID;

	return VALID;
}

static inline void aeon_update_dentry_csum(struct aeon_dentry *de)
{
	de->csum = cpu_to_le32(crc32_le(SEED,
			       (unsigned char *)de,
			       AEON_DENTRY_CSIZE));
}

static inline int is_persisted_inode(struct aeon_inode *pi)
{
	__le32 temp;

	temp = cpu_to_le32(crc32_le(SEED,
				    (unsigned char *)pi,
				    AEON_INODE_CSIZE));
	if (temp != pi->csum)
		return INVALID;

	return VALID;
}

static inline void aeon_update_inode_csum(struct aeon_inode *pi)
{
	pi->csum = cpu_to_le32(crc32_le(SEED,
					(unsigned char *)pi,
					AEON_INODE_CSIZE));
}

static inline int aeon_super_block_persisted(struct aeon_super_block *aeon_sb)
{
	__le32 temp;

	temp = cpu_to_le32(crc32_le(SEED,
				    (unsigned char *)aeon_sb,
				    AEON_INODE_CSIZE));
	if (temp != aeon_sb->s_csum)
		return INVALID;

	return VALID;
}

static inline void aeon_update_super_block_csum(struct aeon_super_block *aeon_sb)
{
	aeon_sb->s_csum = cpu_to_le32(crc32_le(SEED,
					       (unsigned char *)aeon_sb,
					       AEON_INODE_CSIZE));
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

/* super.c */
struct aeon_range_node *aeon_alloc_inode_node(struct super_block *);
void aeon_free_inode_node(struct aeon_range_node *node);
struct aeon_range_node *aeon_alloc_dir_node(struct super_block *sb);
void aeon_free_dir_node(struct aeon_range_node *node);
struct aeon_range_node *aeon_alloc_block_node(struct super_block *sb);
void aeon_free_block_node(struct aeon_range_node *node);
struct aeon_range_node *aeon_alloc_extent_node(struct super_block *sb);
void aeon_free_extent_node(struct aeon_range_node *node);

/* balloc.h */
int aeon_alloc_block_free_lists(struct super_block *sb);
void aeon_delete_free_lists(struct super_block *sb);
unsigned long aeon_count_free_blocks(struct super_block *sb);
void aeon_init_blockmap(struct super_block *sb);
int aeon_insert_range_node(struct rb_root *tree,
			   struct aeon_range_node *new_node, enum node_type);
bool aeon_find_range_node(struct rb_root *tree, unsigned long key,
			  enum node_type type, struct aeon_range_node **ret_node);
void aeon_destroy_range_node_tree(struct super_block *sb, struct rb_root *tree);
int aeon_new_data_blocks(struct super_block *sb,
	struct aeon_inode_info_header *sih, unsigned long *blocknr,
	unsigned long start_blk, unsigned int num, int cpu);
int aeon_insert_blocks_into_free_list(struct super_block *sb,
				      unsigned long blocknr,
				      int num, unsigned short btype);
int aeon_dax_get_blocks(struct inode *inode, sector_t iblock,
			unsigned long max_blocks, u32 *bno, bool *new,
			bool *boundary, int create);
u64 aeon_get_new_inode_block(struct super_block *sb, int cpuid, u32 start_ino);
void aeon_init_new_inode_block(struct super_block *sb, u32 ino);
unsigned long aeon_get_new_dentry_block(struct super_block *sb, u64 *de_addr);
unsigned long aeon_get_new_symlink_block(struct super_block *sb,
					 u64 *pi_addr, int cpuid);
unsigned long aeon_get_new_extents_block(struct super_block *sb);
u64 aeon_get_new_blk(struct super_block *sb);
u64 aeon_get_xattr_blk(struct super_block *sb);

/* dir.c */
int aeon_insert_dir_tree(struct super_block *sb,
			 struct aeon_inode_info_header *sih,
			 const char *name, int namelen,
			 struct aeon_dentry *direntry);
u64 aeon_add_dentry(struct dentry *dentry, u32 ino,
		    u64 pi_addr, int inc_link);
int aeon_remove_dentry(struct dentry *dentry, int dec_link,
		       struct aeon_inode *update, struct aeon_dentry *de);
int aeon_get_dentry_address(struct super_block *sb,
			    struct aeon_inode *pi, u64 *de_addr);
struct aeon_dentry *aeon_find_dentry(struct super_block *sb,
				     struct aeon_inode *pi,
				     struct inode *inode, const char *name,
				     unsigned long name_len);
void aeon_delete_dir_tree(struct super_block *sb,
			  struct aeon_inode_info_header *sih);
struct aeon_dentry *aeon_dotdot(struct super_block *sb,
				struct dentry *dentry);
void aeon_set_link(struct inode *dir, struct aeon_dentry *de,
		   struct inode *inode, int update_times);
int aeon_empty_dir(struct inode *inode);
void aeon_free_invalid_dentry_list(struct super_block *sb,
				   struct aeon_inode_info_header *sih);

/* rebuild.c */
int aeon_rebuild_dir_inode_tree(struct super_block *sb, struct aeon_inode *pi,
				u64 pi_addr, struct inode *inode);
void aeon_rebuild_inode_cache(struct super_block *sb);

/* symlink.c */
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
