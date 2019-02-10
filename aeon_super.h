#ifndef __AEON_SUPER_H
#define __AEON_SUPER_H

#include "aeon.h"

#define AEON_SB_SIZE            64
#define AEON_SB_CSIZE           (AEON_SB_SIZE - CHECKSUM_SIZE)

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

	char   pad[3];
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

#ifdef CONFIG_AEON_FS_NUMA
	struct numa_maps *nm;
	int numa_nodes;
	int num_lists;
#endif

	struct free_list *candidate;
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

#ifdef CONFIG_AEON_FS_NUMA
static inline u64 AEON_HEAD(struct super_block *sb, int numa_id)
{
	return -1;
}
#else
static inline u64 AEON_HEAD(struct super_block *sb)
{
	return (u64)AEON_SB(sb)->virt_addr;
}
#endif

/*
 * Get the persistent memory's address
 */
static inline struct aeon_super_block *aeon_get_super(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return (struct aeon_super_block *)sbi->virt_addr;
}

/**
 * aeon_get_address() - Translate an offset
 * the beginning of the aeon instance to a PMEM address.
 * @sb: super block
 * @offset: The offset from the head address
 * @offset2: The offset from the "offset" address
 */
static inline
void *aeon_get_address(struct super_block *sb, u64 offset, u64 offset2)
{
	return offset ? (void *)(AEON_HEAD(sb) + offset + offset2) : NULL;
}

static inline
u64 aeon_get_address_u64(struct super_block *sb, u64 offset, u64 offset2)
{
	return offset ? (AEON_HEAD(sb) + offset + offset2) : 0;
}

static inline int aeon_get_reference(struct super_block *sb, u64 block,
				     void *dram, void **nvmm, size_t size)
{
	int rc = 0;

	*nvmm = aeon_get_address(sb, block, 0);
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

static inline int nr_numa_nodes(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < num_online_cpus(); i++) {
		if (ret == cpu_to_mem(i))
			ret++;
	}

	return ret;
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
