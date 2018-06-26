#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/dax.h>
#include <linux/pfn_t.h>
#include <linux/genhd.h>
#include <linux/dcache.h>
#include <linux/backing-dev-defs.h>
#include <linux/parser.h>

#include "super.h"
#include "inode.h"
#include "balloc.h"
#include "mprotect.h"

static struct kmem_cache *aeon_inode_cachep;
static struct kmem_cache *aeon_range_node_cachep;
int wprotect = 0;

static struct inode *aeon_alloc_inode(struct super_block *sb)
{
	struct aeon_inode_info *si;

	si = kmem_cache_alloc(aeon_inode_cachep, GFP_NOFS);
	if (!si)
		return NULL;

	si->vfs_inode.i_version = 1;

	return &si->vfs_inode;
}

static void aeon_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct aeon_inode_info *si = AEON_I(inode);

	aeon_dbg("%s: ino %lu\n", __func__, inode->i_ino);
	kmem_cache_free(aeon_inode_cachep, si);
}

static void aeon_destroy_inode(struct inode *inode)
{
	aeon_dbg("%s: %lu\n", __func__, inode->i_ino);
	call_rcu(&inode->i_rcu, aeon_i_callback);
}

static void aeon_put_super(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map;
	int i;

	/* It's unmount time, so unmap the aeon memory */
	if (sbi->virt_addr) {
		/* Save everything before blocknode mapping! */
	}

	aeon_delete_free_lists(sb);

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		aeon_dbg("CPU %d: inode allocated %d, freed %d\n",
			i, inode_map->allocated, inode_map->freed);
	}
	kfree(sbi->inode_maps);

	kfree(sbi);
}

static struct super_operations aeon_sops = {
	.alloc_inode   = aeon_alloc_inode,
	.destroy_inode = aeon_destroy_inode,
	.put_super     = aeon_put_super,
};

void aeon_err_msg(struct super_block *sb, const char *fmt, ...)
{
	va_list args;

	printk(KERN_CRIT "aeon error: ");
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);

}

static void aeon_free_range_node(struct aeon_range_node *node)
{
	kmem_cache_free(aeon_range_node_cachep, node);
}

void aeon_free_dir_node(struct aeon_range_node *node)
{
	aeon_free_range_node(node);
}

void aeon_free_inode_node(struct aeon_range_node *node)
{
	aeon_free_range_node(node);
}

static struct aeon_range_node *aeon_alloc_range_node(struct super_block *sb)
{
	struct aeon_range_node *p;

	p = (struct aeon_range_node *)kmem_cache_zalloc(aeon_range_node_cachep, GFP_NOFS);

	return p;
}

struct aeon_range_node *aeon_alloc_inode_node(struct super_block *sb)
{
	return aeon_alloc_range_node(sb);
}

struct aeon_range_node *aeon_alloc_dir_node(struct super_block *sb)
{
	return aeon_alloc_range_node(sb);
}

static void init_once(void *foo)
{
	struct aeon_inode_info *vi = foo;
	inode_init_once(&vi->vfs_inode);
}

static int __init init_inodecache(void)
{
	aeon_inode_cachep = kmem_cache_create("aeon_inode_cache",
					       sizeof(struct aeon_inode_info),
					       0, (SLAB_RECLAIM_ACCOUNT |
						   SLAB_MEM_SPREAD), init_once);
	if (aeon_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before
	 * we destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(aeon_inode_cachep);
}

static int __init init_rangenode_cache(void)
{
	aeon_range_node_cachep = kmem_cache_create("aeon_range_node_cache",
					sizeof(struct aeon_range_node),
					0, (SLAB_RECLAIM_ACCOUNT |
					SLAB_MEM_SPREAD), NULL);
	if (aeon_range_node_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_rangenode_cache(void)
{
	kmem_cache_destroy(aeon_range_node_cachep);
}

static int aeon_get_nvmm_info(struct super_block *sb, struct aeon_sb_info *sbi)
{
	void *virt_addr = NULL;
	pfn_t __pfn_t;
	long size;
	struct dax_device *dax_dev;
	int ret;


	ret = bdev_dax_supported(sb, PAGE_SIZE);
	aeon_dbg("%s: dax_supported = %d; bdev->super=0x%p",
		 __func__, ret, sb->s_bdev->bd_super);
	if (ret) {
		aeon_dbg("device does not support DAX\n");
		return ret;
	}

	sbi->s_bdev = sb->s_bdev;

	dax_dev = fs_dax_get_by_host(sb->s_bdev->bd_disk->disk_name);
	if (!dax_dev) {
		aeon_err(sb, "Couldn't retrieve DAX device.\n");
		return -EINVAL;
	}
	sbi->s_dax_dev = dax_dev;

	size = dax_direct_access(sbi->s_dax_dev, 0, LONG_MAX/PAGE_SIZE,
				 &virt_addr, &__pfn_t) * PAGE_SIZE;
	if (size <= 0) {
		aeon_err(sb, "direct_access failed\n");
		return -EINVAL;
	}

	sbi->virt_addr = virt_addr;

	if (!sbi->virt_addr) {
		aeon_err(sb, "ioremap of the aeon image failed(1)\n");
		return -EINVAL;
	}

	sbi->phys_addr = pfn_t_to_pfn(__pfn_t) << PAGE_SHIFT;
	sbi->initsize = size;

	aeon_dbg("%s: dev %s, phys_addr 0x%llx, virt_addr 0x%lx, size %ld\n",
		__func__, sbi->s_bdev->bd_disk->disk_name,
		sbi->phys_addr, (unsigned long)sbi->virt_addr, sbi->initsize);
	return 0;
}

static void aeon_root_check(struct super_block *sb, struct aeon_inode *root_pi)
{
	if (!S_ISDIR(le16_to_cpu(root_pi->i_mode)))
		aeon_err(sb, "root is not a directory\n");
}

enum {
	Opt_init, Opt_dax
};

static const match_table_t tokens = {
	{ Opt_init,  "init" },
	{ Opt_dax,   "dax" },
};

static int aeon_parse_options(char *options, struct aeon_sb_info *sbi, bool remount)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_init:
			set_opt(sbi->s_mount_opt, FORMAT);
			break;
		case Opt_dax:
			set_opt(sbi->s_mount_opt, DAX);
			break;
		default:
			break;
		}
	}

	return 0;
}

static void aeon_set_blocksize(struct super_block *sb, unsigned long size)
{
	int bits;

	bits = fls(size) - 1;
	sb->s_blocksize_bits = bits;
	sb->s_blocksize = (1 << bits);
}

static void aeon_init_super_block(struct super_block *sb, unsigned long size)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_super_block *aeon_sb = sbi->aeon_sb;

	aeon_memunlock_super(sb);

	aeon_sb->s_magic = cpu_to_le32(AEON_MAGIC);
	aeon_sb->s_size = cpu_to_le64(size);
	aeon_sb->s_blocksize = AEON_DEF_BLOCK_SIZE_4K;

	aeon_memlock_super(sb);
}

static void aeon_init_root_inode(struct super_block *sb, struct aeon_inode *root_i)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	aeon_memunlock_inode(sb, root_i);

	root_i->i_mode = cpu_to_le16(sbi->mode | S_IFDIR);
	root_i->i_uid = cpu_to_le32(from_kuid(&init_user_ns, sbi->uid));
	root_i->i_gid = cpu_to_le32(from_kgid(&init_user_ns, sbi->gid));
	root_i->i_links_count = cpu_to_le16(2);
	root_i->i_flags = 0;
	root_i->i_size = cpu_to_le64(sb->s_blocksize);
	root_i->i_atime = root_i->i_mtime = root_i->i_ctime =
		cpu_to_le32(get_seconds());
	root_i->aeon_ino = cpu_to_le64(AEON_ROOT_INO);
	root_i->valid = 1;

	aeon_memlock_inode(sb, root_i);
}

static struct aeon_inode *aeon_init(struct super_block *sb, unsigned long size)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode *root_i = NULL;

	sbi->aeon_sb = aeon_get_super(sb);
	root_i = aeon_get_inode_by_ino(sb, AEON_ROOT_INO);
	if (sbi->s_mount_opt & AEON_MOUNT_FORMAT) {
		aeon_init_super_block(sb, size);
		aeon_init_root_inode(sb, root_i);
	}

	aeon_init_blockmap(sb);

	if (aeon_init_inode_inuse_list(sb) < 0) {
		aeon_err(sb, "%s is failed\n", __func__, "aeon_init_inuse_list");
		return NULL;
	}

	return root_i;
}

static int aeon_fill_super(struct super_block *sb, void *data, int silent)
{
	struct aeon_inode *root_pi;
	struct aeon_sb_info *sbi;
	struct inode *root_i;
	struct inode_map *inode_map;
	unsigned long blocksize;
	unsigned long virt_off;
	int ret = -EINVAL;
	int i;

	aeon_dbg("%s:START\n", __func__);

	sbi = kzalloc(sizeof(struct aeon_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sb->s_fs_info = sbi;

	ret = aeon_get_nvmm_info(sb, sbi);
	if (ret)
		goto out0;

	sbi->uid  = current_fsuid();
	sbi->gid  = current_fsgid();
	sbi->cpus = num_online_cpus();
	sbi->map_id = 0;
	sbi->num_blocks = (unsigned long)(sbi->initsize) >> PAGE_SHIFT;
	sbi->blocksize = AEON_DEF_BLOCK_SIZE_4K;
	aeon_set_blocksize(sb, sbi->blocksize);
	sbi->mode = (0777);	/* it will be changed */
	sbi->max_inodes_in_page = 32;
	sbi->inode_maps = kcalloc(sbi->cpus, sizeof(struct inode_map), GFP_KERNEL);
	if(!sbi->inode_maps) {
		ret = -ENOMEM;
		goto out0;
	}

	virt_off = sbi->initsize / sbi->cpus;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		if (i == 0)
			sbi->inode_maps[i].virt_addr = sbi->virt_addr + AEON_DEF_BLOCK_SIZE_4K;
		else
			sbi->inode_maps[i].virt_addr = sbi->virt_addr + virt_off * i;
		mutex_init(&inode_map->inode_table_mutex);
		inode_map->inode_inuse_tree = RB_ROOT;
	}
	aeon_dbg("The number of cpus - %d\n", sbi->cpus);
	aeon_dbg("block device - %s\n", sb->s_bdev->bd_disk->disk_name);

	mutex_init(&sbi->s_lock);

	if (aeon_alloc_block_free_lists(sb)) {
		ret = -ENOMEM;
		goto out1;
	}

	ret = aeon_parse_options(data, sbi, 0);
	if (ret) {
		aeon_err(sb, "%s: failed to parse aeon command line options.", __func__);
		goto out2;
	}

	root_pi = aeon_init(sb, sbi->initsize);
	if (sbi->aeon_sb->s_magic != AEON_MAGIC)
		goto out2;
	else

	blocksize = le32_to_cpu(sbi->aeon_sb->s_blocksize);
	aeon_set_blocksize(sb, blocksize);

	aeon_root_check(sb, root_pi);

	sb->s_magic = le32_to_cpu(sbi->aeon_sb->s_magic);
	sb->s_op = &aeon_sops;

	root_i = aeon_iget(sb, AEON_ROOT_INO);
	if (IS_ERR(root_i)) {
		ret = -ENOMEM;
		aeon_err(sb, "%s ERR root_i\n", __func__);
		goto out2;
	}
	aeon_dbg("%s: root_i ino - %lu\n", __func__, root_i->i_ino);
	aeon_dbg("%s: root_pi ino - %u\n", __func__, le32_to_cpu(root_pi->aeon_ino));

	sb->s_root = d_make_root(root_i);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto out2;
	}
	aeon_dbg("%s:FINISH\n", __func__);

	return 0;
out2:
	aeon_delete_free_lists(sb);
out1:
	aeon_dbg("%s: free inode_maps\n", __func__);
	kfree(sbi->inode_maps);
out0:
	kfree(sbi);

	aeon_dbg("%s failed: return %d\n", __func__, ret);
	return ret;
}

static struct dentry *aeon_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, aeon_fill_super);
}

static struct file_system_type aeon_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "aeon",
	.mount		= aeon_mount,
	.kill_sb	= kill_block_super,
};

static int __init init_aeon_fs(void)
{
	int err;

	aeon_info("---HELLO AEON---\n");

	err = init_inodecache();
	if (err)
		goto out2;

	err = init_rangenode_cache();
	if (err)
		goto out1;

	err = register_filesystem(&aeon_fs_type);
	if (err)
		goto out;

	return 0;
out:
	destroy_rangenode_cache();
out1:
	destroy_inodecache();
out2:
	return err;
}

static void __exit exit_aeon_fs(void)
{
	aeon_dbg("---GOOD BYE AEON---\n");
	unregister_filesystem(&aeon_fs_type);
	//remove_proc_entry(proc_dirname, NULL);
	destroy_inodecache();
	destroy_rangenode_cache();
}

MODULE_AUTHOR("Fumiya Shigemitsu");
MODULE_DESCRIPTION("AEON: A Persistent Memory File System");
MODULE_LICENSE("GPL");

module_init(init_aeon_fs)
module_exit(exit_aeon_fs)
