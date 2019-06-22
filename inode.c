#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/iomap.h>
#include <linux/posix_acl.h>
#include <linux/mm.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/dax.h>

#include "aeon.h"
#include "aeon_super.h"
#include "aeon_balloc.h"
#include "aeon_extents.h"
#include "aeon_dir.h"

#define AEON_BLOCK_TYPE_MAX 1
unsigned int blk_type_to_shift[AEON_BLOCK_TYPE_MAX] = {12};
uint32_t blk_type_to_size[AEON_BLOCK_TYPE_MAX] = {0x1000};


static inline int aeon_insert_inodetree(struct super_block *sb,
					struct aeon_range_node *new_node,
					int cpu)
{
	struct rb_root *tree;
	struct inode_map *inode_map;
	int ret;

	inode_map = aeon_get_inode_map(sb, cpu);
	tree = &inode_map->inode_inuse_tree;
	ret = aeon_insert_range_node(tree, new_node, NODE_INODE);
	if (ret)
		aeon_err(sb, "ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

int aeon_init_inode_inuse_list(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_range_node *range_node;
	struct inode_map *inode_map;
	struct aeon_region_table *art;
	int i;
	int ret;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = aeon_get_inode_map(sb, i);
		mutex_lock(&inode_map->inode_table_mutex);
		art = AEON_R_TABLE(inode_map);
		range_node = aeon_alloc_inode_node(sb);
		if (range_node == NULL) {
			mutex_unlock(&inode_map->inode_table_mutex);
			return -ENOMEM;
		}
		range_node->range_low = 0;
		range_node->range_high = le32_to_cpu(art->i_range_high);
		ret = aeon_insert_inodetree(sb, range_node, i);
		if (ret) {
			aeon_err(sb, "%s failed\n", __func__);
			aeon_free_inode_node(range_node);
			mutex_unlock(&inode_map->inode_table_mutex);
			return ret;
		}
		inode_map->num_range_node_inode = 1;
		inode_map->first_inode_range = range_node;

		mutex_unlock(&inode_map->inode_table_mutex);
	}

	return 0;
}

int aeon_get_inode_address(struct super_block *sb,
			   u32 ino, u64 *pi_addr,
			   struct aeon_dentry *de)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode *pi;
	u64 addr = le64_to_cpu(de->d_inode_addr);

	if (addr <= 0 || addr > sbi->last_addr) {
		aeon_err(sb, "out of bounds addr 0x%llx last 0x%llx\n",
			 addr, sbi->last_addr);
		return -ENOENT;
	}

	*pi_addr = AEON_HEAD(sb) + addr;

	pi = (struct aeon_inode *)(*pi_addr);
	if (ino != le32_to_cpu(pi->aeon_ino)) {
		aeon_err(sb, "%s:ino %u, pi_ino %u\n", __func__, ino,
			 le32_to_cpu(pi->aeon_ino));
		aeon_dbg("0x%llx\n", *pi_addr);
		return -EINVAL;
	}

	return 0;
}

u32 aeon_inode_by_name(struct inode *dir, struct qstr *entry)
{
	struct super_block *sb = dir->i_sb;
	struct aeon_dentry *direntry;

	direntry = aeon_find_dentry(sb, NULL, dir, entry->name, entry->len);
	if (direntry == NULL)
		return 0;

	aeon_dbgv("%s: %s", __func__, direntry->name);
	return direntry->ino;
}

void aeon_init_file(struct aeon_inode *pi,
		    struct aeon_extent_header *aeh)
{
	if (!le16_to_cpu(pi->i_exblocks)) {
		pi->i_new = 0;
		pi->i_exblocks++;
		aeon_init_extent_header(aeh);
	}
}

static inline
void aeon_init_header(struct super_block *sb,
		      struct aeon_inode_info_header *sih,
		      u64 pi_addr)
{
	sih->pi_addr = pi_addr;
	sih->rb_tree = RB_ROOT;
	sih->num_vmas = 0;
	sih->de_info = NULL;
	init_rwsem(&sih->dax_sem);
	mutex_init(&sih->truncate_mutex);
	rwlock_init(&sih->i_meta_lock);
#ifdef CONFIG_AEON_FS_XATTR
	init_rwsem(&sih->xattr_sem);
#endif
#ifdef CONFIG_AEON_FS_COMPRESSION
	sih->rb_ctree = RB_ROOT;
#endif
}

void aeon_set_file_ops(struct inode *inode)
{
	inode->i_op = &aeon_file_inode_operations;
	inode->i_fop = &aeon_dax_file_operations;
	inode->i_mapping->a_ops = &aeon_dax_aops;
}

static inline void fill_new_aeon_inode(struct super_block *sb,
				       struct aeon_inode_info_header *sih,
				       struct inode *inode,
				       struct aeon_mdata *am)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_inode *pidir = am->pidir;
	u64 i_addr_offset;
	u64 d_addr_offset;
	u64 p_addr_offset;

	i_addr_offset = am->pi_addr - AEON_HEAD(sb);
	d_addr_offset = am->de_addr - AEON_HEAD(sb);
	p_addr_offset = (u64)pidir  - AEON_HEAD(sb);

	aeon_memunlock_inode(sb, pi);

	pi->deleted = 0;
	pi->i_new = 1;
	pi->i_links_count = cpu_to_le16(inode->i_nlink);
	pi->i_mtime = pi->i_atime = pi->i_ctime =
		pi->i_create_time = cpu_to_le32(current_time(inode).tv_sec);
	pi->i_uid = cpu_to_le32(i_uid_read(inode));
	pi->i_gid = cpu_to_le32(i_gid_read(inode));
	pi->aeon_ino = cpu_to_le32(inode->i_ino);
	pi->parent_ino = cpu_to_le32(pidir->aeon_ino);
	pi->i_block = 0;
	pi->i_blocks = 0;
	pi->i_xattr = 0;
	pi->i_pinode_addr = cpu_to_le64(p_addr_offset);
	pi->i_inode_addr = cpu_to_le64(i_addr_offset);
	pi->i_dentry_addr = cpu_to_le64(d_addr_offset);
	pi->i_size = cpu_to_le64(inode->i_size);
	pi->i_mode = cpu_to_le16(inode->i_mode);
	pi->dev.rdev =  cpu_to_le32(am->rdev);
	pi->i_exblocks = 0;
#ifdef CONFIG_AEON_FS_COMPRESSION
	pi->i_original_size = 0;
#endif

	aeon_init_extent_header(&pi->aeh);

	pi->valid = 1;

	aeon_update_inode_csum(pi);

	aeon_memlock_inode(sb, pi);
}

static void aeon_init_inode_flags(struct inode *inode)
{
	inode->i_flags |= S_DAX;
	inode->i_flags |= S_SYNC;
}

struct inode *aeon_new_vfs_inode(enum aeon_new_inode_type type,
				 struct inode *dir, struct aeon_mdata *am)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct aeon_inode_info *si;
	struct aeon_inode_info_header *sih = NULL;
	int err;

	inode = new_inode(sb);
	if (!inode) {
		err = -ENOMEM;
		goto out;
	}

	inode_init_owner(inode, dir, am->mode);
	inode->i_blocks = inode->i_size = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_size = am->size;
	inode->i_mode = am->mode;
	inode->i_ino = am->ino;
	aeon_init_inode_flags(inode);
	aeon_dbgv("%s: allocating inode %u @ 0x%llx\n",
		  __func__, am->ino, am->pi_addr);

	switch (type) {
	case TYPE_CREATE:
		inode->i_op = &aeon_file_inode_operations;
		if (compression)
			inode->i_fop = &aeon_compress_file_operations;
		else
			inode->i_fop = &aeon_dax_file_operations;
		inode->i_mapping->a_ops = &aeon_dax_aops;
		break;
	case TYPE_MKDIR:
		inode->i_op = &aeon_dir_inode_operations;
		inode->i_fop = &aeon_dir_operations;
		inode->i_mapping->a_ops = &aeon_dax_aops;
		set_nlink(inode, 2);
		break;
	case TYPE_SYMLINK:
		inode->i_op = &aeon_symlink_inode_operations;
		break;
	case TYPE_MKNOD:
		init_special_inode(inode, am->mode, am->rdev);
		inode->i_op = &aeon_special_inode_operations;
		break;
	default:
		aeon_dbg("Unknown new inode type %d\n", type);
		break;
	}

	si = AEON_I(inode);
	sih = &si->header;
	aeon_init_header(sb, sih, am->pi_addr);

	fill_new_aeon_inode(sb, sih, inode, am);

	return inode;
out:
	make_bad_inode(inode);
	iput(inode);
	return ERR_PTR(err);
}

static int aeon_alloc_unused_inode(struct super_block *sb, int cpuid,
				   u32 *ino, struct inode_map *inode_map)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_range_node *i, *next_i;
	struct rb_node *temp, *next;
	struct aeon_region_table *art;
	unsigned long next_range_low;
	u32 MAX_INODE = 1UL << 31;
	u32 new_ino;

	art = AEON_R_TABLE(inode_map);
	i = inode_map->first_inode_range;

	temp = &i->node;
	next = rb_next(temp);

	if (!next) {
		next_i = NULL;
		next_range_low = MAX_INODE;
	} else {
		next_i = container_of(next, struct aeon_range_node, node);
		next_range_low = next_i->range_low;
	}

	new_ino = i->range_high + 1;

	if (next_i && new_ino == (next_range_low - 1)) {
		/* Fill the gap completely */
		i->range_high = next_i->range_high;
		rb_erase(&next_i->node, &inode_map->inode_inuse_tree);
		aeon_free_inode_node(next_i);
		inode_map->num_range_node_inode--;
	} else if (new_ino < (next_range_low - 1)) {
		/* Aligns to left */
		i->range_high = new_ino;
	} else {
		aeon_err(sb, "%s: ERROR: new ino %lu, next low %lu\n", __func__,
			 new_ino, next_range_low);
		return -ENOSPC;
	}

	*ino =  new_ino  * sbi->cpus + cpuid;
	art->i_range_high = le32_to_cpu(i->range_high);
	art->allocated++;
	art->i_allocated++;

	return 0;
}

static u64 search_imem_addr(struct super_block *sb, int cpu_id, u32 ino)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_region_table *art = aeon_get_rtable(sb, cpu_id);
	unsigned long blocknr;
	unsigned long internal_ino;
	u64 addr;

	internal_ino = (((ino - cpu_id - 1) / sbi->cpus) %
			AEON_I_NUM_PER_PAGE);
	blocknr = le64_to_cpu(art->i_blocknr);

	blocknr <<= AEON_SHIFT;
	internal_ino <<= AEON_I_SHIFT;
	addr = aeon_get_address_u64(sb, blocknr, internal_ino);

	aeon_dbgv("%s ino %u addr 0x%llx\n", __func__, ino, addr);
	return addr;
}

static int aeon_get_new_inode_address(struct super_block *sb, u32 free_ino,
				      u64 *pi_addr, int cpuid)
{
	unsigned long ret;

	ret = aeon_get_new_inode_block(sb, cpuid, free_ino);
	if (ret <= 0)
		goto err;

	*pi_addr = search_imem_addr(sb, cpuid, free_ino);
	if (*pi_addr == 0)
		goto err;

	return 0;

err:
	aeon_err(sb, "can't alloc ino %u's inode address\n", free_ino);
	return -ENOSPC;
}

static u64 aeon_reclaim_inode(struct inode_map *inode_map, u32 *ino)
{
	struct icache *im;
	u64 addr;

	im = list_first_entry(&inode_map->im->imem_list, struct icache, imem_list);
	addr = im->addr;
	*ino = im->ino;
	list_del(&im->imem_list);
	aeon_free_icache(im);
	im = NULL;

	return addr;
}

int aeon_new_aeon_inode(struct super_block *sb, struct aeon_mdata *am)
{
#ifdef CONFIG_AEON_FS_PERCPU_INODEMAP
#else
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);
#endif
	struct inode_map *inode_map;
	int cpu_id ;
	int err = 0;
	u64 pi_addr = 0;
	u32 free_ino = 0;

#ifdef CONFIG_AEON_FS_PERCPU_INODEMAP
	cpu_id = aeon_get_cpuid(sb);
#else
	cpu_id = aeon_sb->s_map_id;
	aeon_sb->s_map_id = (aeon_sb->s_map_id + 1) % sbi->cpus;
#endif
	inode_map = aeon_get_inode_map(sb, cpu_id);

	mutex_lock(&inode_map->inode_table_mutex);

	if (!list_empty(&inode_map->im->imem_list)) {
		am->pi_addr = aeon_reclaim_inode(inode_map, &free_ino);
		am->ino = free_ino;
		mutex_unlock(&inode_map->inode_table_mutex);
		goto finish;
	}

	err = aeon_alloc_unused_inode(sb, cpu_id, &free_ino, inode_map);
	if (err) {
		aeon_err(sb, "%s: alloc inode num failed %d\n", __func__, err);
		mutex_unlock(&inode_map->inode_table_mutex);
		return err;
	}

	err = aeon_get_new_inode_address(sb, free_ino, &pi_addr, cpu_id);
	if (err) {
		aeon_err(sb, "%s: get inode addr failed %d\n", __func__, err);
		mutex_unlock(&inode_map->inode_table_mutex);
		return err;
	}

	mutex_unlock(&inode_map->inode_table_mutex);

	am->ino = free_ino;
	am->pi_addr = pi_addr;

finish:
	return err;
}

static inline u64 aeon_get_created_inode_addr(struct super_block *sb, u32 ino)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct i_valid_list *meta;
	struct i_valid_list *mdend;
	struct i_valid_child_list *data;
	struct i_valid_child_list *ddend;
	u64 pi_addr = 0;

	/* TODO:
	 */
	spin_lock(&sbi->s_ivl_lock);
	list_for_each_entry_safe(meta, mdend,
				 &sbi->ivl->i_valid_list, i_valid_list) {
		list_for_each_entry_safe(data, ddend,
					 &meta->ivcl->i_valid_child_list,
					 i_valid_child_list) {
			if (data->ino == ino) {
				pi_addr = data->addr;
				list_del(&data->i_valid_child_list);
				kfree((void *)data);
				if (list_empty(&meta->i_valid_list)) {
					list_del(&meta->i_valid_list);
					kfree((void *)meta);
				}
				goto found;
			}
		}
	}

	aeon_err(sb, "not found corresponding inode\n");
	aeon_dbg("%s: %u\n", __func__, ino);
	spin_unlock(&sbi->s_ivl_lock);
	BUG();

found:
	spin_unlock(&sbi->s_ivl_lock);
	return pi_addr;
}

static u64 aeon_get_inode_addr_on_pmem(struct super_block *sb, u32 ino)
{
	u64 addr = 0;

	if (ino == AEON_ROOT_INO)
		addr = aeon_get_reserved_inode_addr(sb, ino);
	else
		addr = aeon_get_created_inode_addr(sb, ino);

	return addr;
}

static int aeon_rebuild_inode(struct super_block *sb, struct inode *inode,
			      u64 ino, u64 pi_addr, int rebuild_dir)
{
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih  = &si->header;
	struct aeon_inode *pi = (struct aeon_inode *)pi_addr;
	int err;

	aeon_init_header(sb, sih, 0755);
	sih->pi_addr = pi_addr;

	if (ino == AEON_ROOT_INO)
		AEON_SB(sb)->si = si;

	if (pi->i_new)
		goto end;

	switch (le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFREG:
		err = aeon_rebuild_extenttree(sb, pi, inode);
		if (err) {
			aeon_err(sb, "Can't rebuild extent tree\n");
			return err;
		}
		break;
	case S_IFDIR:
		err = aeon_rebuild_dir_inode_tree(sb, pi, pi_addr, inode);
		if (err) {
			aeon_err(sb, "Can't rebuld dir tree\n");
			return err;
		}
		break;
	default:
		break;
	}

end:
	return 0;
}

void aeon_set_inode_flags(struct inode *inode,
			  struct aeon_inode *pi,
			  unsigned int flags)
{
	inode->i_flags |= S_DAX;
	inode->i_flags |= S_SYNC;
	if (flags & AEON_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & AEON_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & AEON_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
}

/* copy persistent state to struct inode */
static int aeon_read_inode(struct super_block *sb,
			   struct inode *inode, u64 pi_addr)
{
	struct aeon_inode *pi;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	int ret = -EIO;
	unsigned long ino;

	pi = aeon_get_inode(sb, sih);

	inode->i_mode = le16_to_cpu(pi->i_mode);
	i_uid_write(inode, le32_to_cpu(pi->i_uid));
	i_gid_write(inode, le32_to_cpu(pi->i_gid));
	aeon_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));
	ino = le32_to_cpu(pi->aeon_ino);

	if (inode->i_mode == 0 || pi->deleted == 1) {
		ret = -ESTALE;
		aeon_err(sb, "inode->i_mode %lu - delete %ld\n", inode->i_mode, pi->deleted);
		goto bad_inode;
	}

	inode->i_blocks = le64_to_cpu(pi->i_blocks);
	inode->i_mapping->a_ops = &aeon_dax_aops;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &aeon_file_inode_operations;
		inode->i_fop = &aeon_dax_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &aeon_dir_inode_operations;
		inode->i_fop = &aeon_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &aeon_symlink_inode_operations;
		break;
	default:
		init_special_inode(inode, inode->i_mode,
					   le32_to_cpu(pi->dev.rdev));
		inode->i_op = &aeon_special_inode_operations;
		break;
	}

	inode->i_size = le64_to_cpu(pi->i_size);
	inode->i_atime.tv_sec = (__s32)le32_to_cpu(pi->i_atime);
	inode->i_ctime.tv_sec = (__s32)le32_to_cpu(pi->i_ctime);
	inode->i_mtime.tv_sec = (__s32)le32_to_cpu(pi->i_mtime);
	inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
		inode->i_ctime.tv_nsec = 0;
	set_nlink(inode, le16_to_cpu(pi->i_links_count));

	return 0;

bad_inode:
	make_bad_inode(inode);
	return ret;
}

/*
 * Pass ino that was created
 */
struct inode *aeon_iget(struct super_block *sb, u32 ino)
{
	struct inode *inode;
	u64 pi_addr = 0;
	int err;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	pi_addr = aeon_get_inode_addr_on_pmem(sb, ino);

	aeon_dbgv("%s: nvmm 0x%llx\n", __func__, pi_addr);

	if (pi_addr == 0) {
		aeon_err(sb, "%s: failed to get pi_addr for inode %lu\n", __func__, ino);
		err = -EACCES;
		goto fail;
	}

	err = aeon_rebuild_inode(sb, inode, ino, pi_addr, 1);
	if (err) {
		aeon_err(sb, "%s: failed to rebuild inode %lu\n", __func__, ino);
		goto fail;
	}

	err = aeon_read_inode(sb, inode, pi_addr);
	if (unlikely(err)) {
		aeon_err(sb, "%s: failed to read inode %lu\n", __func__, ino);
		goto fail;
	}

	inode->i_sb = sb;

	unlock_new_inode(inode);
	return inode;
fail:
	iget_failed(inode);
	return ERR_PTR(err);
}

void aeon_destroy_icache(struct inode_map *inode_map)
{
	struct icache *im;
	struct icache *dend = NULL;

	list_for_each_entry_safe(im, dend, &inode_map->im->imem_list, imem_list) {
		list_del(&im->imem_list);
		aeon_free_icache(im);
		im = NULL;
	}
}

int aeon_free_dram_resource(struct super_block *sb,
			    struct aeon_inode_info_header *sih)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	int freed = 0;

	if (pi->aeon_ino == 0)
		return 0;

	if (!(S_ISREG(le16_to_cpu(pi->i_mode))) &&
	    !(S_ISDIR(le16_to_cpu(pi->i_mode))))
		return 0;

	if (S_ISDIR(le16_to_cpu(pi->i_mode))) {
		int err;

		err = aeon_free_cached_dentry_blocks(sb, sih);
		if (err) {
			aeon_err(sb, "%s: free_cached_dentry_blocks", __func__);
			return -1;
		}
		aeon_free_invalid_dentry_list(sb, sih);
		if (sih->de_info) {
			kfree(sih->de_info);
			sih->de_info = NULL;
		}
	}
	freed = 1;

	return freed;
}

static inline int aeon_search_inodetree(struct aeon_sb_info *sbi,
					unsigned long ino,
					struct aeon_range_node **ret_node)
{
	struct rb_root *tree;
	struct inode_map *inode_map;
	unsigned long internal_ino;
	int cpu;

	cpu = ino % sbi->cpus;
	inode_map = aeon_get_inode_map(sbi->sb, cpu);
	tree = &inode_map->inode_inuse_tree;
	internal_ino = ino / sbi->cpus;

	return aeon_find_range_node(tree, internal_ino, NODE_INODE, ret_node);
}

static int aeon_free_inode(struct super_block *sb, struct aeon_inode *pi,
			   struct aeon_inode_info_header *sih)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	u32 ino = le32_to_cpu(pi->aeon_ino);
	int cpuid = ino % sbi->cpus;
	struct inode_map *inode_map = aeon_get_inode_map(sb, cpuid);
	struct aeon_region_table *art = AEON_R_TABLE(inode_map);
	struct icache *im;
	int err = 0;

	mutex_lock(&inode_map->inode_table_mutex);

	im = aeon_alloc_icache(sb);
	im->ino = ino;
	im->addr = sih->pi_addr;
	im->independent = 1;
	im->head = im;
	art->freed++;
	list_add(&im->imem_list, &inode_map->im->imem_list);

	mutex_unlock(&inode_map->inode_table_mutex);

	return err;
}

int aeon_free_inode_resource(struct super_block *sb, struct aeon_inode *pi,
			     struct aeon_inode_info_header *sih)
{
	int err;

	pi->deleted = 1;
	pi->valid = 0;

	switch (le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFREG:
		err = aeon_delete_extenttree(sb, sih);
		if (err) {
			aeon_err(sb, "regular\n");
			goto out;
		}
		break;
	case S_IFDIR:
		err = aeon_delete_dir_tree(sb, sih);
		if (err) {
			aeon_err(sb, "directory\n");
			goto out;
		}
		break;
	case S_IFLNK:
		err = aeon_delete_symblock(sb, sih);
		if (err) {
			aeon_err(sb, "symlink\n");
			goto out;
		}
		break;
	default:
		aeon_dbgv("%s: special ino %u\n",
			  __func__, le32_to_cpu(pi->aeon_ino));
		break;
	}

	err = aeon_free_inode(sb, pi, sih);
	if (err)
		goto out;

	return 0;
out:
	aeon_err(sb, "%s: free inode %lu failed\n", __func__, pi->aeon_ino);
	return err;
}

int aeon_update_time(struct inode *inode,
		     struct timespec64 *time, int flags)
{
	struct aeon_inode *pi;

	pi = aeon_get_inode(inode->i_sb, &AEON_I(inode)->header);

	if (flags & S_ATIME) {
		inode->i_atime = *time;
		pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
		flags &= ~S_ATIME;
	}
	if (flags & S_CTIME) {
		inode->i_ctime = *time;
		pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
		flags &= ~S_CTIME;
	}
	if (flags & S_MTIME) {
		inode->i_mtime = *time;
		pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
		flags &= ~S_MTIME;
	}

	return 0;
}

static void aeon_shrink_file(struct super_block *sb,
			     struct inode *inode,
			     struct aeon_extent *ae,
			     loff_t offset, unsigned long iblock)
{
	struct aeon_inode *pi;
	struct aeon_extent_header *aeh;
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	unsigned long off;
	loff_t old_size = inode->i_size;
	int entries;
	int index;
	int length;

	pi = aeon_get_inode(sb, sih);
	aeh = aeon_get_extent_header(pi);

	aeon_dbg("SHRINK\n");
	aeon_dbg("%llu -> %llu\n", old_size, offset);

	WARN_ON(old_size < offset);

	if (offset > old_size)
		dump_stack();

	entries = le16_to_cpu(aeh->eh_entries);
	index = le16_to_cpu(ae->ex_index);
	off = le32_to_cpu(ae->ex_offset);
	length = le32_to_cpu(ae->ex_length);

	if (old_size < offset)
		ae->ex_length = cpu_to_le16(off + length - iblock);

	//aeh->eh_entries = cpu_to_le16(++index);
	entries = entries - index - 1;
	aeon_cutoff_extenttree(sb, sih, pi, entries, index);
}

static void aeon_expand_blocks(struct super_block *sb, struct inode *inode,
			       loff_t offset, unsigned long iblock)
{
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	unsigned long new_blocknr = 0;
	unsigned long old_nblocks;
	unsigned long new_nblocks;
	unsigned long blkbits = inode->i_blkbits;
	loff_t old_size = inode->i_size;
	int allocated;
	int err;

	aeon_dbg("EXPAND\n");
	aeon_dbg("%llu -> %llu\n", old_size, offset);

	WARN_ON(old_size < offset);

	old_nblocks = old_size >> blkbits;
	new_nblocks = iblock - old_nblocks;
	if (!new_nblocks)
		new_nblocks = 1;

	allocated = aeon_new_data_blocks(sb, sih, &new_blocknr,
					 old_nblocks, new_nblocks, ANY_CPU);
	if (allocated <= 0) {
		mutex_unlock(&sih->truncate_mutex);
		return;
	}

	err = aeon_update_extent(sb, inode, new_blocknr, old_nblocks, allocated);
	if (err) {
		aeon_err(sb, "failed to update extent\n");
		mutex_unlock(&sih->truncate_mutex);
		return;
	}

	clean_bdev_aliases(sb->s_bdev, new_blocknr, allocated);
	err = sb_issue_zeroout(sb, new_blocknr, allocated, GFP_NOFS);
	if (err)
		aeon_err(sb, "%s: ERROR\n", __func__);

}

void aeon_truncate_blocks(struct inode *inode, loff_t offset)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_extent *ae;
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	unsigned long iblock = offset >> inode->i_blkbits;

	mutex_lock(&sih->truncate_mutex);

	ae = aeon_search_extent(sb, sih, iblock);
	if (ae)
		aeon_shrink_file(sb, inode, ae, offset, iblock);
	else
		aeon_expand_blocks(sb, inode, offset, iblock);

	mutex_unlock(&sih->truncate_mutex);

	return err;
}

static void aeon_setattr_to_pmem(const struct inode *inode,
				 struct aeon_inode *pi,
				 const struct iattr *attr)
{
	unsigned int ia_valid = attr->ia_valid;

	if (ia_valid & ATTR_UID)
		pi->i_uid = cpu_to_le32(i_uid_read(inode));
	if (ia_valid & ATTR_GID)
		pi->i_gid = cpu_to_le32(i_gid_read(inode));
	if (ia_valid & ATTR_ATIME)
		pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	if (ia_valid & ATTR_MTIME)
		pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	if (ia_valid & ATTR_CTIME)
		pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	if (ia_valid & ATTR_MODE)
		pi->i_mode = cpu_to_le16(inode->i_mode);
}

static int aeon_setsize(struct inode *inode, loff_t newsize)
{
	struct aeon_inode *pi;
	int err;

	pi = aeon_get_inode(inode->i_sb, &AEON_I(inode)->header);

	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	      S_ISLNK(inode->i_mode)))
		return -EINVAL;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;

	/* dio_wait ? */
	inode_dio_wait(inode);

	err = iomap_zero_range(inode, newsize, PAGE_ALIGN(newsize) - newsize,
			       NULL, &aeon_iomap_ops);
	if (err)
		return err;
	dax_sem_down_write(&AEON_I(inode)->header);
	aeon_truncate_blocks(inode, newsize);
	truncate_setsize(inode, newsize);
	pi->i_size = cpu_to_le64(newsize);
	dax_sem_up_write(&AEON_I(inode)->header);

	inode->i_mtime = inode->i_ctime = current_time(inode);
	pi->i_mtime = pi->i_ctime = cpu_to_le64(inode->i_mtime.tv_sec);
	return 0;
}

int aeon_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = d_inode(dentry);
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	unsigned int ia_valid = iattr->ia_valid;
	unsigned int attr_mask = attr_mask;
	int err = -EACCES;

	if (!pi)
		return err;

	err = setattr_prepare(dentry, iattr);
	if (err)
		return err;

	setattr_copy(inode, iattr);
	aeon_setattr_to_pmem(inode, pi, iattr);

	attr_mask = ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE | ATTR_ATIME
		| ATTR_MTIME | ATTR_CTIME;
	ia_valid = ia_valid & attr_mask;

	if (ia_valid == 0)
		return 0;

	if (iattr->ia_valid & ATTR_SIZE && iattr->ia_size != inode->i_size) {
		err = aeon_setsize(inode, iattr->ia_size);
		if (err)
			return err;
	}

	return 0;
}

static int aeon_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	return dax_writeback_mapping_range(mapping,
					   mapping->host->i_sb->s_bdev, wbc);
}

const struct address_space_operations aeon_dax_aops = {
	.writepages	= aeon_writepages,
	.direct_IO	= noop_direct_IO,
	.set_page_dirty	= noop_set_page_dirty,
	.invalidatepage	= noop_invalidatepage,
};
