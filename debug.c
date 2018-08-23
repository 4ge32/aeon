#include <linux/debugfs.h>
#include <linux/slab.h>

#include "aeon.h"


static struct dentry *aeon_debugfs_root;
static DEFINE_MUTEX(aeon_stat_mutex);
static LIST_HEAD(aeon_stat_list);

struct aeon_stat_info {
	struct aeon_sb_info *sbi;

	struct list_head stat_list;

	/* free list */
	unsigned long block_start;
	unsigned long block_end;
	unsigned long num_free_blocks;

	/* curr free block range */
	unsigned long range_low;
	unsigned long range_high;

	/* about inode map */
	int allocated;
	int freed;

	/* super block information on disk */
	unsigned int s_num_inodes;
};

static void aeon_update_stats(struct aeon_sb_info *sbi, struct aeon_stat_info *si, int cpu)
{
	struct free_list *free_list;
	struct rb_root *tree;
	struct aeon_range_node *curr;
	struct rb_node *temp;
	struct inode_map *inode_map;
	struct aeon_super_block *aeon_sb = aeon_get_super(sbi->sb);
	struct aeon_region_table *art;

	free_list = &sbi->free_lists[cpu];

	si->block_start = free_list->block_start;
	si->block_end = free_list->block_end;
	si->num_free_blocks = free_list->num_free_blocks;

	tree = &(free_list->block_free_tree);
	temp = &(free_list->first_node->node);
	curr = container_of(temp, struct aeon_range_node, node);

	si->range_low = curr->range_low;
	si->range_high = curr->range_high;

	inode_map = &sbi->inode_maps[cpu];
	art = AEON_R_TABLE(inode_map);

	si->allocated = le64_to_cpu(art->allocated);
	si->freed = le64_to_cpu(art->freed);

	si->s_num_inodes = aeon_sb->s_num_inodes;
}

static int stat_show(struct seq_file *s, void *v)
{
	struct aeon_stat_info *si;
	unsigned long free_blocks = 0;
	unsigned long used_blocks = 0;
	int allocated_inodes = 0;
	int freed_inodes = 0;
	int i = 0;

	mutex_lock(&aeon_stat_mutex);
	list_for_each_entry(si, &aeon_stat_list, stat_list) {
		if (i == 0) {
			seq_printf(s, "=========== Basic Info ==========\n");
			seq_printf(s, "The number of cpu cores: %d\n", si->sbi->cpus);
			seq_printf(s, "The head virtual address: 0x%lx\n", (unsigned long)si->sbi->virt_addr);
			seq_printf(s, "The initsize: %ld\n", si->sbi->initsize);
			seq_printf(s, "\n");
		}
		aeon_update_stats(si->sbi, si, i);

		seq_printf(s, "========== cpu core:  %d ==========\n", i++);
		seq_printf(s, "block_start: %lu, block_end: %lu\n", si->block_start, si->block_end);
		seq_printf(s, "Free blocks: %lu\n", si->num_free_blocks);
		seq_printf(s, "Used blocks: %lu\n", (si->block_end - si->block_start + 1) - si->num_free_blocks);
		seq_printf(s, "Current free range: %lu - %lu\n", si->range_low, si->range_high);

		seq_printf(s, "Allocated inodes: %d\n", si->allocated);
		seq_printf(s, "Freed inodes: %d\n", si->freed);

		seq_printf(s, "\n");

		free_blocks += si->num_free_blocks;
		used_blocks += ((si->block_end - si->block_start + 1) - si->num_free_blocks);
		allocated_inodes += si->allocated;
		freed_inodes += si->freed;
	}
	seq_printf(s, "========== TOTAL ==========\n");
	seq_printf(s, "Free block: %lu\n", free_blocks);
	seq_printf(s, "Used block: %lu\n", used_blocks);
	seq_printf(s, "Allocated inodes: %d\n", allocated_inodes);
	seq_printf(s, "freed inodes: %d\n", freed_inodes);
	seq_printf(s, "Allocated inodes: %u\n", si->s_num_inodes);
	mutex_unlock(&aeon_stat_mutex);

	return 0;
}

static int stat_imem_show(struct seq_file *s, void *v)
{
	struct aeon_stat_info *si;
	struct inode_map *inode_map;
	int i = 0;

	mutex_lock(&aeon_stat_mutex);
	list_for_each_entry(si, &aeon_stat_list, stat_list) {
		if (i == 0) {
			seq_printf(s, "=========== imem cache Info ==========\n");
		}
		aeon_update_stats(si->sbi, si, i);

		seq_printf(s, "cpu-id: %d\n", i);

		inode_map = &si->sbi->inode_maps[i];

		if (inode_map->im) {
			struct imem_cache *im;
			int count = 0;
			list_for_each_entry(im, &inode_map->im->imem_list, imem_list) {
				seq_printf(s, "ino: %3lu : 0x%llx", im->ino, im->addr);

				if (count % 2 == 1)
					seq_printf(s, "\n");
				else
					seq_printf(s, "  ");
				count++;
			}
			seq_printf(s, "inodes cache: %d\n\n", count);
		}
		i++;

	}
	mutex_unlock(&aeon_stat_mutex);

	return 0;
}

static int stat_den_show(struct seq_file *s, void *v)
{
	struct aeon_stat_info *si;
	struct aeon_sb_info *sbi;
	struct aeon_inode *pi;
	struct aeon_dentry_map *de_map;
	struct aeon_dentry *de;
	unsigned long blocknr;
	int num_entry = 0;
	int global;
	int internal;

	seq_printf(s, "========== dentry map ==========\n");

	si = list_first_entry(&aeon_stat_list, struct aeon_stat_info, stat_list);
	sbi = si->sbi;
	pi = aeon_get_reserved_inode(sbi->sb, AEON_ROOT_INO);
	de_map = aeon_get_first_dentry_map(sbi->sb, pi);
	if (!de_map)
		return 0;

	num_entry = le64_to_cpu(de_map->num_dentries);
	global = 0;
	internal = 2;

	mutex_lock(&aeon_stat_mutex);

	seq_printf(s, "dentries %u\n\n", num_entry);
	seq_printf(s, "%8s : %8s : %8s : %8s : %8s\n", "internal", "global", "blocknr", "ino", "name");

	while (num_entry > 2) {
		if (internal == 8) {
			global++;
			internal = 0;
		}

		blocknr = le64_to_cpu(de_map->block_dentry[global]);
		de = (struct aeon_dentry *)(sbi->virt_addr +
					   (blocknr << AEON_SHIFT) +
					   (internal << AEON_D_SHIFT));
		seq_printf(s, "%8u : %8u : %8lu : %8u : %8s\n", internal, global, blocknr, le32_to_cpu(de->ino), de->name);

		internal++;
		num_entry--;
	}

	mutex_unlock(&aeon_stat_mutex);

	return 0;
}

static int stat_open(struct inode *inode, struct file *file)
{
	return single_open(file, stat_show, inode->i_private);
}

static int stat_imem_open(struct inode *inode, struct file *file)
{
	return single_open(file, stat_imem_show, inode->i_private);
}

static int stat_den_open(struct inode *inode, struct file *file)
{
	return single_open(file, stat_den_show, inode->i_private);
}

static const struct file_operations stat_fops = {
	.owner   = THIS_MODULE,
	.open    = stat_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static const struct file_operations stat_imem_fops = {
	.owner   = THIS_MODULE,
	.open    = stat_imem_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static const struct file_operations stat_den_fops = {
	.owner   = THIS_MODULE,
	.open    = stat_den_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

int aeon_build_stats(struct aeon_sb_info *sbi)
{
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		struct aeon_stat_info *si;

		si = kzalloc(sizeof(struct aeon_stat_info), GFP_KERNEL);
		if (!si)
			return -ENOMEM;
		sbi->stat_info = si;
		si->sbi = sbi;

		si->block_start = 0;
		si->block_end = 0;

		list_add(&si->stat_list, &aeon_stat_list);
	}

	return 0;
}

void aeon_destroy_stats(struct aeon_sb_info *sbi)
{
	struct aeon_stat_info *data;
	struct aeon_stat_info *dend = NULL;

	mutex_lock(&aeon_stat_mutex);
	list_for_each_entry_safe(data, dend, &aeon_stat_list, stat_list) {
		list_del(&data->stat_list);
		kfree((void *)data);
	}
	mutex_unlock(&aeon_stat_mutex);
}

int __init aeon_create_root_stats(void)
{
	struct dentry *free_list_file;
	struct dentry *imem_cache_file;
	struct dentry *d_allocated;

	aeon_debugfs_root = debugfs_create_dir("aeon", NULL);
	if (!aeon_debugfs_root)
		return -ENOMEM;

	free_list_file = debugfs_create_file("free_list", S_IRUGO, aeon_debugfs_root,
				   NULL, &stat_fops);

	if (!free_list_file) {
		debugfs_remove(aeon_debugfs_root);
		aeon_debugfs_root = NULL;
		return -ENOMEM;
	}

	imem_cache_file = debugfs_create_file("imem_cache", S_IRUGO, aeon_debugfs_root,
				   NULL, &stat_imem_fops);

	if (!imem_cache_file) {
		debugfs_remove_recursive(aeon_debugfs_root);
		aeon_debugfs_root = NULL;
		return -ENOMEM;
	}

	d_allocated = debugfs_create_file("dentries", S_IRUGO, aeon_debugfs_root,
				   NULL, &stat_den_fops);
	if (!d_allocated) {
		debugfs_remove_recursive(aeon_debugfs_root);
		aeon_debugfs_root = NULL;
		return -ENOMEM;
	}

	return 0;
}

void aeon_destroy_root_stats(void)
{
	if (!aeon_debugfs_root)
		return;

	debugfs_remove_recursive(aeon_debugfs_root);
	aeon_debugfs_root = NULL;
}
