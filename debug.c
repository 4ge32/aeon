#include <linux/debugfs.h>
#include <linux/slab.h>

#include "aeon.h"
#include "aeon_balloc.h"
#include "aeon_dir.h"


static struct dentry *aeon_debugfs_root;
static DEFINE_MUTEX(aeon_stat_mutex);
static LIST_HEAD(aeon_stat_list);

struct aeon_stat_info {
	struct aeon_sb_info *sbi;

	struct list_head stat_list;

	/* free list */
	int index;
	unsigned long block_start;
	unsigned long block_end;
	unsigned long num_free_blocks;
	unsigned long alloc_data_count;
	unsigned long freed_data_count;
	unsigned long alloc_data_pages;
	unsigned long freed_data_pages;
	unsigned long num_blocknode;

	unsigned long i_blocknr;

	/* curr free block range */
	unsigned long f_range_low;
	unsigned long f_range_high;
	unsigned long l_range_low;
	unsigned long l_range_high;

	/* about inode map */
	int allocated;
	int freed;

	/* super block information on disk */
	unsigned int s_num_inodes;
};

static void aeon_update_stats(struct aeon_sb_info *sbi,
			      struct aeon_stat_info *si, int cpu)
{
	struct free_list *free_list;
	struct rb_root *tree;
	struct aeon_range_node *curr;
	struct rb_node *temp;
	struct inode_map *inode_map;
	struct aeon_super_block *aeon_sb = aeon_get_super(sbi->sb);
	struct aeon_region_table *art;
	//struct tt_root *tt_tree;
	//struct tt_node *tt_temp;

	free_list = &sbi->free_lists[cpu];
	inode_map = aeon_get_inode_map(sbi->sb, cpu);
	art = AEON_R_TABLE(inode_map);
	//tt_tree = &art->block_free_tree;
	//tt_temp = tt_tree->tt_node;
	//curr = container_of(tt_temp, struct aeon_range_node, tt_node);


	/* Store data related to pmem region */
	si->index = free_list->index;
	si->block_start = free_list->block_start;
	si->block_end = free_list->block_end;
	si->num_free_blocks = le64_to_cpu(art->num_free_blocks);
	si->alloc_data_count = le64_to_cpu(art->alloc_data_count);
	si->freed_data_count = le64_to_cpu(art->freed_data_count);
	si->alloc_data_pages = le64_to_cpu(art->alloc_data_pages);
	si->freed_data_pages = le64_to_cpu(art->freed_data_pages);
	si->num_blocknode = free_list->num_blocknode;

	/* inode page's allocation state */
	si->i_blocknr = le64_to_cpu(art->i_blocknr);

	tree = &(free_list->block_free_tree);
	temp = &(free_list->first_node->node);
	curr = container_of(temp, struct aeon_range_node, node);
	si->f_range_low = curr->range_low;
	si->f_range_high = curr->range_high;
	//aeon_dbg("R:%lu\n", curr->range_low);
	//aeon_dbg("R*%lu\n", curr->range_high);
	temp = &(free_list->last_node->node);
	curr = container_of(temp, struct aeon_range_node, node);
	si->l_range_low = curr->range_low;
	si->l_range_high = curr->range_high;

	si->allocated = le64_to_cpu(art->allocated);
	si->freed = le64_to_cpu(art->freed);

	si->s_num_inodes = aeon_sb->s_num_inodes;
}

static void do_print(struct seq_file *s, struct rb_node *temp)
{
	struct aeon_range_node *curr = NULL;

	curr = container_of(temp, struct aeon_range_node, node);
	if (curr == NULL)
		return;

	do_print(s, temp->rb_left);
	seq_printf(s, ": %lu - %lu :", curr->range_low, curr->range_high);
	do_print(s, temp->rb_right);
}

static void other_free_nodes_printf(struct seq_file *s,
				    struct free_list *free_list,
				    unsigned short btype)
{
	struct rb_root *tree;
	struct rb_node *temp;

	spin_lock(&free_list->s_lock);
	tree = &(free_list->block_free_tree);
	temp = tree->rb_node;
	do_print(s, temp);
	spin_unlock(&free_list->s_lock);

	seq_printf(s, "\n");
}

static int stat_show(struct seq_file *s, void *v)
{
	struct aeon_stat_info *si;
	unsigned long free_blocks = 0;
	unsigned long used_blocks = 0;
	unsigned short btype = 0;
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

		seq_printf(s, "========== cpu core:  %d ==========\n", i);
		seq_printf(s, "===Free list===\n");
		seq_printf(s, "index %d\n", si->index);
		seq_printf(s, "block_start: %lu, block_end: %lu\n",
			   si->block_start, si->block_end);
		seq_printf(s, "Free blocks: %lu\n", si->num_free_blocks);
		seq_printf(s, "Used blocks: %lu\n",
			   (si->block_end - si->block_start + 1) - si->num_free_blocks);
		seq_printf(s, "Alloc data count %lu\n", si->alloc_data_count);
		seq_printf(s, "Alloc data pages %lu\n", si->alloc_data_pages);
		seq_printf(s, "Freed data count %lu\n", si->freed_data_pages);
		seq_printf(s, "Freed data pages %lu\n", si->freed_data_pages);
		seq_printf(s, "num_blocknode    %lu\n", si->num_blocknode);
		seq_printf(s, "Current free range (first node): %lu - %lu\n",
			   si->f_range_low, si->f_range_high);
		seq_printf(s, "Current free range (last node): %lu - %lu\n",
			   si->l_range_low, si->l_range_high);
		other_free_nodes_printf(s, aeon_get_free_list(si->sbi->sb, i),btype);
		seq_printf(s, "blocknr of latest head: %lu\n", si->i_blocknr);

		seq_printf(s, "Allocated inodes: %d\n", si->allocated);
		seq_printf(s, "Freed inodes: %d\n", si->freed);

		seq_printf(s, "\n");

		free_blocks += si->num_free_blocks;
		used_blocks += ((si->block_end - si->block_start + 1) - si->num_free_blocks);
		allocated_inodes += si->allocated;
		freed_inodes += si->freed;

		i++;
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
	struct aeon_region_table *art;
	int cpu_id = 0;

	mutex_lock(&aeon_stat_mutex);
	list_for_each_entry(si, &aeon_stat_list, stat_list) {
		struct aeon_inode *pi;
		int count = 0;
		unsigned long blocknr;
		unsigned long internal_ino;
		u64 addr;
		u32 head_ino;
		u32 ino;
		int i;
		int space = 0;

		if (cpu_id == 0) {
			seq_printf(s, "=========== imem cache Info ==========\n");
			seq_printf(s, "head address 0x%llx\n",
				   (u64)si->sbi->virt_addr);
		}
		aeon_update_stats(si->sbi, si, cpu_id);
		seq_printf(s, "cpu-id: %d\n", cpu_id);
		inode_map = aeon_get_inode_map(si->sbi->sb, cpu_id);
		art = AEON_R_TABLE(inode_map);
		head_ino = le32_to_cpu(art->i_head_ino);
		if (head_ino < si->sbi->cpus * 2)
			space = 1;
		ino = head_ino;
		if (inode_map->im) {
			struct imem_cache *im;
			int count = 0;
			list_for_each_entry(im, &inode_map->im->imem_list,
					    imem_list) {
				seq_printf(s, "ino: %3u : 0x%llx",
					   im->ino, im->addr);

				if (count % 4 == 0)
					seq_printf(s, "\n");
				else
					seq_printf(s, "  ");
				count++;
			}
			seq_printf(s, "inodes cache: %d\n\n", count);
		}
		for (i = 0;
		     i < AEON_I_NUM_PER_PAGE; i++) {
			blocknr = le64_to_cpu(art->i_blocknr);
			internal_ino = ((ino - cpu_id) / si->sbi->cpus) %
						AEON_I_NUM_PER_PAGE;
			addr = (u64)si->sbi->virt_addr + (blocknr << AEON_SHIFT)
				+ (internal_ino << AEON_I_SHIFT);
			pi = (struct aeon_inode *)addr;
			if (pi->valid || pi->deleted)
				goto next;
			seq_printf(s, "ino: %3u : 0x%llx", ino, addr);
			if (count % 4 == 0)
				seq_printf(s, "\n");
			else
				seq_printf(s, "  ");
			count++;
next:
			ino += si->sbi->cpus;
		}
		seq_printf(s, "inodes cache: %d\n\n", count);
		cpu_id++;
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
	u64 pi_addr = 0;
	int num_entry = 0;
	int global;
	int internal;
	int err;

	seq_printf(s, "========== dentry map ==========\n");

	si = list_first_entry(&aeon_stat_list, struct aeon_stat_info, stat_list);
	sbi = si->sbi;
	seq_printf(s, "head: 0x%llx\n", (u64)sbi->virt_addr);

	pi = aeon_get_reserved_inode(sbi->sb, AEON_ROOT_INO);
	de_map = aeon_get_dentry_map(sbi->sb, &sbi->si->header);
	if (!de_map)
		return 0;

	num_entry = le64_to_cpu(de_map->num_dentries);
	global = 0;
	internal = 0;

	mutex_lock(&aeon_stat_mutex);

	seq_printf(s, "dentries %u\n\n", num_entry);
	seq_printf(s, "  %8s : %8s : %8s : %8s : %15s : %8s\n",
		   "internal", "global", "blocknr", "ino", "name", "type");

	while (num_entry > 0) {
		if (internal == AEON_INTERNAL_ENTRY) {
			global++;
			internal = 0;
		}

		blocknr = le64_to_cpu(de_map->block_dentry[global]);
		de = (struct aeon_dentry *)((u64)sbi->virt_addr +
					   (blocknr << AEON_SHIFT) +
					   (internal << AEON_D_SHIFT));
		if (!de->valid) {
			seq_printf(s, "X %8u : %8u : %8lu : %8u : %15s : ?\n",
				   internal, global, blocknr,
				   le32_to_cpu(de->ino), de->name);
			internal++;
			continue;
		}


		seq_printf(s, "O %8u : %8u : %8lu : %8u : %15s : ",
			   internal, global, blocknr,
			   le32_to_cpu(de->ino), de->name);
		if (le32_to_cpu(de->ino) == AEON_ROOT_INO) {
			seq_printf(s, "%8s\n", "DIRECTORY");
			goto next;
		} else if (le32_to_cpu(de->ino) == 0) {
			seq_printf(s, "%8s\n", "DIRECTORY");
			goto next;
		}

		err = aeon_get_inode_address(sbi->sb, le32_to_cpu(de->ino),
					     &pi_addr, de);
		if (err) {
			internal++;
			seq_printf(s, "%8s\n", "ERROR");
			continue;
		}
		pi = (struct aeon_inode *)pi_addr;
		switch (le16_to_cpu(pi->i_mode) & S_IFMT) {
		case S_IFREG:
			seq_printf(s, "%8s  ", "REGULAR");
			break;
		case S_IFDIR:
			seq_printf(s, "%8s  ", "DIRECTORY");
			break;
		case S_IFLNK:
			seq_printf(s, "%8s ", "SYMLINK");
			break;
		default:
			seq_printf(s, "%8s  ", "SPECIAL");
			break;
		}

		seq_printf(s, "%llx\n", pi_addr);

next:

		num_entry--;
		internal++;
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

	free_list_file = debugfs_create_file("free_list", S_IRUGO,
					     aeon_debugfs_root,
					     NULL, &stat_fops);

	if (!free_list_file) {
		debugfs_remove(aeon_debugfs_root);
		aeon_debugfs_root = NULL;
		return -ENOMEM;
	}

	imem_cache_file = debugfs_create_file("imem_cache", S_IRUGO,
					      aeon_debugfs_root,
					      NULL, &stat_imem_fops);

	if (!imem_cache_file) {
		debugfs_remove_recursive(aeon_debugfs_root);
		aeon_debugfs_root = NULL;
		return -ENOMEM;
	}

	d_allocated = debugfs_create_file("dentries", S_IRUGO,
					  aeon_debugfs_root,
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
