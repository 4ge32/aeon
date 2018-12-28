#ifndef __AEON_SUPER_H
#define __AEON_SUPER_H

#include "aeon.h"

#define AEON_SB_SIZE            512
#define AEON_SB_CSIZE           (512 - CHECKSUM_SIZE)

extern int fs_persisted;

struct aeon_super_block {
	spinlock_t s_lock;
	u8     s_wakeup;

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

	char   pad[444];
	__le32 s_csum;              /* checksum of this sb */
} __attribute((__packed__));

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

	/* protects i_valid_list */
	spinlock_t s_ivl_lock;

	/* store root inode info */
	struct aeon_inode_info *si;

	/* used show debug info */
	struct aeon_stat_info *stat_info;

	/* used in recovery process */
	struct opaque_list *oq;

	struct mb_cache *s_ea_block_cache;
};


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

static inline u64 aeon_get_addr_off(struct aeon_sb_info *sbi)
{
	return (u64)sbi->virt_addr;
}

static inline int aeon_super_block_persisted(struct aeon_super_block *aeon_sb)
{
	__le32 temp;

	temp = cpu_to_le32(crc32_le(SEED,
				    (unsigned char *)aeon_sb,
				    AEON_SB_CSIZE));
	if (temp != aeon_sb->s_csum)
		return 0;

	return 1;
}

static inline void aeon_update_super_block_csum(struct aeon_super_block *aeon_sb)
{
	aeon_sb->s_csum = cpu_to_le32(crc32_le(SEED,
					       (unsigned char *)aeon_sb,
					       AEON_SB_CSIZE));
}

static inline void aeon_wakeup(struct super_block *sb)
{
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);

	aeon_sb->s_wakeup = 1;
}

static inline void aeon_sleep(struct super_block *sb)
{
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);

	aeon_sb->s_wakeup = 0;
}

static inline int is_shutdown_ok(struct super_block *sb)
{
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);

	if (aeon_sb->s_wakeup)
		return 0;
	return 1;
}


struct aeon_range_node *aeon_alloc_inode_node(struct super_block *);
void aeon_free_inode_node(struct aeon_range_node *node);
struct aeon_range_node *aeon_alloc_dir_node(struct super_block *sb);
void aeon_free_dir_node(struct aeon_range_node *node);
struct aeon_range_node *aeon_alloc_block_node(struct super_block *sb);
void aeon_free_block_node(struct aeon_range_node *node);
struct aeon_range_node *aeon_alloc_extent_node(struct super_block *sb);
void aeon_free_extent_node(struct aeon_range_node *node);

#endif
