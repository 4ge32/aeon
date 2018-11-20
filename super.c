#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/dax.h>
#include <linux/pfn_t.h>
#include <linux/genhd.h>
#include <linux/dcache.h>
#include <linux/backing-dev-defs.h>
#include <linux/parser.h>
#include <linux/cred.h>
#include <linux/statfs.h>

#include "aeon.h"
#include "xattr.h"

static struct kmem_cache *aeon_inode_cachep;
static struct kmem_cache *aeon_range_node_cachep;
int wprotect = 0;
unsigned int aeon_dbgmask;

module_param(wprotect, int, 0444);
MODULE_PARM_DESC(wprotect, "Write-protect pmem region and use CR0.WP to allow updates");


static struct inode *aeon_alloc_inode(struct super_block *sb)
{
	struct aeon_inode_info *si;

	si = kmem_cache_alloc(aeon_inode_cachep, GFP_NOFS);
	if (!si)
		return NULL;

	atomic64_set(&si->vfs_inode.i_version, 1);

	return &si->vfs_inode;
}

static void aeon_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct aeon_inode_info *si = AEON_I(inode);

	kmem_cache_free(aeon_inode_cachep, si);
}

static void aeon_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, aeon_i_callback);
}

static void aeon_put_super(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map;
	struct aeon_region_table *art;
	int i;

	/* It's unmount time, so unmap the aeon memory */
	if (sbi->virt_addr) {
		/* Save everything before blocknode mapping! */
	}

	aeon_delete_free_lists(sb);
	aeon_destroy_stats(sbi);

	if (sbi->s_ea_block_cache) {
		aeon_xattr_destroy_cache(sbi->s_ea_block_cache);
		sbi->s_ea_block_cache = NULL;
	}

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		art = AEON_R_TABLE(inode_map);
		aeon_dbg("CPU %d: inode allocated %llu, freed %llu\n",
			 i, le64_to_cpu(art->allocated), le64_to_cpu(art->freed));
	}
	kfree(sbi->oq);
	kfree(sbi->spare_oq);
	kfree(sbi->inode_maps);

	kfree(sbi);

	aeon_dbg("Unmount filesystem\n");
}

static int aeon_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	//BUG();
	return 0;
}

static void aeon_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	int destroy = 0;
	int ret;

	if (!sih) {
		aeon_err(sb, "%s: ino %lu sih is NULL!\n",
			 __func__, inode->i_ino);
		goto out;
	}

	if (sih->de_info != NULL)
		aeon_free_invalid_dentry_list(sb, sih);

	if (!inode->i_nlink && !is_bad_inode(inode)) {
		if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
			goto out;

		if (pi) {
			if (pi->aeon_ino == 0) {
				aeon_dbg("%lu: What happend?\n", inode->i_ino);
				pi->aeon_ino = le32_to_cpu(inode->i_ino);
			}
			ret = aeon_free_inode_resource(sb, pi, sih);
			if (ret)
				goto out;
		}

		destroy = 1;
		pi = NULL;

		inode->i_mtime = inode->i_ctime = current_time(inode);
		inode->i_size = 0;
	}
out:
	if (destroy == 0) {
		//aeon_dbgv("%s: destroying %lu\n", __func__, inode->i_ino);
		aeon_free_dram_resource(sb, sih);
	}

	truncate_inode_pages(&inode->i_data, 0);

	clear_inode(inode);
}

static int aeon_statfs(struct dentry *d, struct kstatfs *buf)
{
	struct super_block *sb = d->d_sb;
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);
	struct aeon_sb_info *sbi = AEON_SB(sb);

	buf->f_type = AEON_MAGIC;
	buf->f_bsize = sb->s_blocksize;

	buf->f_blocks = sbi->num_blocks;
	buf->f_bfree = buf->f_bavail = aeon_count_free_blocks(sb);
	buf->f_files = aeon_sb->s_num_inodes;
	buf->f_namelen = AEON_NAME_LEN;

	return 0;
}

static struct super_operations aeon_sops = {
	.alloc_inode   = aeon_alloc_inode,
	.destroy_inode = aeon_destroy_inode,
	.put_super     = aeon_put_super,
	.write_inode   = aeon_write_inode,
	.evict_inode   = aeon_evict_inode,
	.statfs        = aeon_statfs,
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

void aeon_free_inode_node(struct aeon_range_node *node)
{
	aeon_free_range_node(node);
}

void aeon_free_dir_node(struct aeon_range_node *node)
{
	aeon_free_range_node(node);
}

void aeon_free_block_node(struct aeon_range_node *node)
{
	aeon_free_range_node(node);
}

void aeon_free_extent_node(struct aeon_range_node *node)
{
	aeon_free_range_node(node);
}

static struct aeon_range_node *aeon_alloc_range_node(struct super_block *sb)
{
	struct aeon_range_node *p;

	p = (struct aeon_range_node *)kmem_cache_zalloc(aeon_range_node_cachep,
							GFP_NOFS);

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

struct aeon_range_node *aeon_alloc_block_node(struct super_block *sb)
{
	return aeon_alloc_range_node(sb);
}

struct aeon_range_node *aeon_alloc_extent_node(struct super_block *sb)
{
	return aeon_alloc_range_node(sb);
}

static int aeon_get_nvmm_info(struct super_block *sb, struct aeon_sb_info *sbi)
{
	void *virt_addr = NULL;
	pfn_t __pfn_t;
	long size;
	struct dax_device *dax_dev;

	if (!bdev_dax_supported(sb->s_bdev, AEON_DEF_BLOCK_SIZE_4K)) {
		aeon_dbg("device does not support DAX\n");
		return -EINVAL;
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

	return 0;
}

static int aeon_root_check(struct super_block *sb, struct aeon_inode *root_pi)
{
	if (!S_ISDIR(le16_to_cpu(root_pi->i_mode))) {
		aeon_err(sb, "root is not a directory\n");
		goto err;
	}

	if (le32_to_cpu(root_pi->aeon_ino) != AEON_ROOT_INO) {
		aeon_err(sb, "root has invalid inode number\n");
		goto err;
	}

	return 0;
err:
	aeon_err(sb, "%s: 0x%px", __func__, root_pi);
	return 1;
}

static int aeon_super_block_check(struct super_block *sb)
{
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);

	if (le32_to_cpu(aeon_sb->s_magic) != AEON_MAGIC) {
		aeon_err(sb, " has invalid magic number");
		goto err;
	}

	if (le32_to_cpu(aeon_sb->s_cpus) != AEON_SB(sb)->cpus) {
		aeon_err(sb, "not matching the number of cpu cores");
		goto err;
	}

	return 1;
err:
	aeon_err(sb, "%s: 0x%px", __func__, aeon_sb);
	return 0;
}

enum {
	Opt_init, Opt_dax, Opt_dbgmask, Opt_user_xattr, Opt_nouser_xattr,
	Opt_wprotect, Opt_err,
};

static const match_table_t tokens = {
	{ Opt_init,		"init"	     },
	{ Opt_dax,		"dax"	     },
	{ Opt_wprotect,		"wprotect"   },
	{ Opt_dbgmask,		"dbgmask=%u" },
	{ Opt_user_xattr,	"user_xattr"},
	{ Opt_nouser_xattr,	"nouser_xattr"},
	{ Opt_err,		"NULL"},
};

static int aeon_parse_options(char *options, struct aeon_sb_info *sbi,
			      bool remount)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_init:
			aeon_info("MKFS AEON\n");
			set_opt(sbi->s_mount_opt, FORMAT);
			break;
		case Opt_dax:
			set_opt(sbi->s_mount_opt, DAX);
			break;
		case Opt_wprotect:
			set_opt(sbi->s_mount_opt, PROTECT);
			aeon_info("AEON: Enabling write protection (CR0.WP)\n");
			break;
		case Opt_dbgmask:
			if (match_int(&args[0], &option))
				goto bad_val;
			aeon_dbgmask = option;
			break;
#ifdef CONFIG_AEON_FS_XATTR
		case Opt_user_xattr:
			set_opt(sbi->s_mount_opt, XATTR_USER);
			break;
		case Opt_nouser_xattr:
			clear_opt(sbi->s_mount_opt, XATTR_USER);
			break;
#else
		case Opt_user_xattr:
		case Opt_nouser_xattr:
			aeon_info("(no)user_xattr options not supported\n");
			break;
#endif
		default:
			break;
		}
	}

	return 0;
bad_val:
	aeon_info("Bad value '%s' for mount option %s'\n'", args[0].from, p);
	return -EINVAL;
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

	aeon_sb->s_map_id = 0;
	aeon_sb->s_cpus = cpu_to_le16(sbi->cpus);
	aeon_sb->s_magic = cpu_to_le32(AEON_MAGIC);
	aeon_sb->s_size = cpu_to_le64(size);
	aeon_sb->s_blocksize = AEON_DEF_BLOCK_SIZE_4K;
	aeon_sb->s_num_inodes = 1;
	aeon_sb->s_csum = SEED;

	aeon_memlock_super(sb);
}

static void aeon_init_root_inode(struct super_block *sb,
				 struct aeon_inode *root_i)
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
	root_i->aeon_ino = cpu_to_le32(AEON_ROOT_INO);
	root_i->parent_ino = 0;
	root_i->valid = 1;
	root_i->deleted = 0;
	root_i->i_new = 1;

	aeon_update_inode_csum(root_i);
	aeon_memlock_inode(sb, root_i);
}

static void aeon_fill_region_table(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_region_table *art;
	struct inode_map *inode_map;
	struct free_list *free_list;
	int cpu_id;

	for (cpu_id = 0; cpu_id < sbi->cpus; cpu_id++) {

		inode_map = &sbi->inode_maps[cpu_id];
		free_list = aeon_get_free_list(sb, cpu_id);
		art = AEON_R_TABLE(inode_map);

		if (sbi->s_mount_opt & AEON_MOUNT_FORMAT) {
			unsigned long range_high;
			unsigned long inode_start;
			unsigned long blocknr;

			inode_start = sbi->cpus + cpu_id;
			range_high = 0;

			art->allocated = 0;
			art->freed = 0;
			art->i_num_allocated_pages = le32_to_cpu(1);
			art->i_range_high = le32_to_cpu(range_high);
			art->b_range_low = le32_to_cpu(free_list->first_node->range_low);
			art->i_allocated = le32_to_cpu(1);
			art->i_head_ino = cpu_to_le32(inode_start);
			blocknr = (((u64)inode_map->i_table_addr -
				   (u64)sbi->virt_addr) >> AEON_SHIFT);
			art->i_blocknr = cpu_to_le64(blocknr);
			art->this_block = cpu_to_le64(blocknr);

			art->num_free_blocks = cpu_to_le64(free_list->num_free_blocks);
			art->alloc_data_count = cpu_to_le64(1);
			art->alloc_data_pages = cpu_to_le64(AEON_PAGES_FOR_INODE);
			art->freed_data_count = 0;
			art->freed_data_pages = 0;
		} else {
			//aeon_dbgv("%s: %u\n", __func__, le32_to_cpu(art->b_range_low));
			free_list->first_node->range_low = le32_to_cpu(art->b_range_low);
			free_list->num_free_blocks = le64_to_cpu(art->num_free_blocks);
		}
	}
}

static struct aeon_inode *aeon_init(struct super_block *sb, unsigned long size)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode *root_i = NULL;
	int inode_start = sbi->cpus;

	sbi->aeon_sb = aeon_get_super(sb);
	root_i = aeon_get_inode_by_ino(sb, AEON_ROOT_INO);
	if (sbi->s_mount_opt & AEON_MOUNT_FORMAT) {
		aeon_init_super_block(sb, size);
		aeon_init_root_inode(sb, root_i);
	} else {
		if (unlikely(root_i->i_new == 1))
			root_i->i_new = 0;
		if (!aeon_super_block_check(sb))
			return NULL;
	}

	aeon_init_blockmap(sb);
	aeon_init_new_inode_block(sb, inode_start);
	aeon_fill_region_table(sb);
	aeon_rebuild_inode_cache(sb);

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
	int ret = -EINVAL;
	int i;

	BUILD_BUG_ON(sizeof(struct aeon_super_block) > AEON_SB_SIZE);
	BUILD_BUG_ON(sizeof(struct aeon_inode) > AEON_INODE_SIZE);
	BUILD_BUG_ON(sizeof(struct aeon_dentry) > AEON_DENTRY_SIZE);
	BUILD_BUG_ON(sizeof(struct aeon_region_table) > AEON_INODE_SIZE);
	BUILD_BUG_ON(sizeof(struct aeon_extent_header) > AEON_EXTENT_HEADER_SIZE);
	BUILD_BUG_ON(sizeof(struct aeon_extent) > AEON_EXTENT_SIZE);

	aeon_dbg("free list    %lu\n", sizeof(struct free_list));
	aeon_dbg("region table %lu\n", sizeof(struct aeon_region_table));
	aeon_dbg("inode map    %lu\n", sizeof(struct inode_map));
	aeon_dbg("sb info      %lu\n", sizeof(struct aeon_sb_info));
	aeon_dbg("super block  %lu\n", sizeof(struct aeon_super_block));
	aeon_dbg("inode        %lu\n", sizeof(struct aeon_inode));
	aeon_dbg("dentry       %lu\n", sizeof(struct aeon_dentry));
	aeon_dbg("extent       %lu\n", sizeof(struct aeon_extent));
	aeon_dbg("extentheader %lu\n", sizeof(struct aeon_extent_header));

	if (num_online_cpus() == 1)
		return -EINVAL;

	sbi = kzalloc(sizeof(struct aeon_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sb->s_fs_info = sbi;

	ret = aeon_get_nvmm_info(sb, sbi);
	if (ret)
		goto out00;

	sbi->sb   = sb;
	sbi->uid  = current_fsuid();
	sbi->gid  = current_fsgid();
	sbi->cpus = num_online_cpus();
	sbi->num_blocks = (unsigned long)(sbi->initsize) >> PAGE_SHIFT;
	sbi->blocksize = AEON_DEF_BLOCK_SIZE_4K;
	aeon_set_blocksize(sb, sbi->blocksize);
	sbi->mode = (0777);	/* it will be changed */
	sbi->oq = kzalloc(sizeof(struct obj_queue), GFP_KERNEL);
	if (!sbi->oq) {
		ret = -ENOMEM;
		goto out000;
	}
	INIT_LIST_HEAD(&sbi->oq->obj_queue);
	sbi->spare_oq = kzalloc(sizeof(struct obj_queue), GFP_KERNEL);
	if (!sbi->spare_oq) {
		ret = -ENOMEM;
		goto out00;
	}
	INIT_LIST_HEAD(&sbi->spare_oq->obj_queue);
	sbi->inode_maps = kcalloc(sbi->cpus,
				  sizeof(struct inode_map), GFP_KERNEL);
	if(!sbi->inode_maps) {
		ret = -ENOMEM;
		goto out0;
	}

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		inode_map->i_table_addr = 0;
		mutex_init(&inode_map->inode_table_mutex);
		inode_map->inode_inuse_tree = RB_ROOT;
	}

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
	if (!root_pi) {
		ret = -EINVAL;
		goto out2;
	}

	if (aeon_root_check(sb, root_pi)) {
		ret = -ENOTDIR;
		goto out2;
	}

#ifdef CONFIG_AEON_FS_XATTR
	sbi->s_ea_block_cache = aeon_xattr_create_cache();
	if (!sbi->s_ea_block_cache)
		goto out2;
#endif

	sb->s_magic = le32_to_cpu(sbi->aeon_sb->s_magic);
	sb->s_op = &aeon_sops;
	sb->s_xattr = aeon_xattr_handlers;
	blocksize = le32_to_cpu(sbi->aeon_sb->s_blocksize);
	aeon_set_blocksize(sb, blocksize);

	ret = aeon_build_stats(sbi);
	if (ret)
		goto out2;

	root_i = aeon_iget(sb, AEON_ROOT_INO);
	if (IS_ERR(root_i)) {
		ret = -ENOMEM;
		aeon_err(sb, "%s ERR root_i\n", __func__);
		goto out3;
	}

	sb->s_root = d_make_root(root_i);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto out3;
	}

	aeon_dbg("Mount filesystem\n");

	return 0;

out3:
	aeon_destroy_stats(sbi);
out2:
	aeon_delete_free_lists(sb);
out1:
	aeon_err(sb, "%s: free inode_maps\n", __func__);
	kfree(sbi->inode_maps);
out0:
	kfree(sbi->oq);
out00:
	kfree(sbi->spare_oq);
out000:
	kfree(sbi);

	aeon_err(sb, "%s failed: return %d\n", __func__, ret);
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

static int __init init_aeon_fs(void)
{
	int err;

	aeon_info("---HELLO AEON---\n");

	err = init_inodecache();
	if (err)
		goto out;

	err = init_rangenode_cache();
	if (err)
		goto out1;

	err = register_filesystem(&aeon_fs_type);
	if (err)
		goto out2;

	err = aeon_create_root_stats();
	if (err)
		goto out3;

	return 0;
out3:
	unregister_filesystem(&aeon_fs_type);
out2:
	destroy_rangenode_cache();
out1:
	destroy_inodecache();
out:
	return err;
}

static void __exit exit_aeon_fs(void)
{
	aeon_dbg("---GOOD BYE AEON---\n");
	unregister_filesystem(&aeon_fs_type);
	destroy_inodecache();
	destroy_rangenode_cache();
	aeon_destroy_root_stats();
}

MODULE_AUTHOR("Fumiya Shigemitsu");
MODULE_DESCRIPTION("AEON: A Persistent Memory File System");
MODULE_LICENSE("GPL");

module_init(init_aeon_fs)
module_exit(exit_aeon_fs)
