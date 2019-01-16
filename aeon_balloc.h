#ifndef __AEON_BALLOC_H
#define __AEON_BALLOC_H

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

static inline struct free_list *aeon_alloc_free_lists(struct super_block *sb)
{
	return alloc_percpu(struct free_list);
}

static inline struct free_list *aeon_get_free_list(struct super_block *sb,
						   int cpu)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	return per_cpu_ptr(sbi->free_lists, cpu);
}

static inline void aeon_free_free_lists(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	free_percpu(sbi->free_lists);
}

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
unsigned long aeon_get_new_symlink_block(struct super_block *sb, u64 *pi_addr);
unsigned long aeon_get_new_extents_block(struct super_block *sb);
u64 aeon_get_new_blk(struct super_block *sb, int cpu_id);
u64 aeon_get_xattr_blk(struct super_block *sb);

#endif
