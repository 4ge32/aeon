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


static inline int aeon_insert_inodetree(struct aeon_sb_info *sbi,
					struct aeon_range_node *new_node,
					int cpu)
{
	struct rb_root *tree;
	int ret;

	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	ret = aeon_insert_range_node(tree, new_node, NODE_INODE);
	if (ret)
		aeon_err(sbi->sb, "ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

static inline int aeon_search_inodetree(struct aeon_sb_info *sbi,
					unsigned long ino,
					struct aeon_range_node **ret_node)
{
	struct rb_root *tree;
	unsigned long internal_ino;
	int cpu;

	cpu = ino % sbi->cpus;
	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	internal_ino = ino / sbi->cpus;

	return aeon_find_range_node(tree, internal_ino, NODE_INODE, ret_node);
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
		inode_map = &sbi->inode_maps[i];
		mutex_lock(&inode_map->inode_table_mutex);
		art = AEON_R_TABLE(inode_map);
		range_node = aeon_alloc_inode_node(sb);
		if (range_node == NULL) {
			mutex_unlock(&inode_map->inode_table_mutex);
			return -ENOMEM;
		}
		range_node->range_low = 0;
		range_node->range_high = le32_to_cpu(art->i_range_high);
		ret = aeon_insert_inodetree(sbi, range_node, i);
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
		aeon_err(sb, "out of bounds i_blocknr 0x%llx last 0x%llx\n",
			 addr, sbi->last_addr);
		return -ENOENT;
	}

	*pi_addr = (u64)sbi->virt_addr + addr;

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

	return direntry->ino;
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
	spin_lock_init(&sih->i_exlock);
#ifdef CONFIG_AEON_FS_XATTR
	init_rwsem(&sih->xattr_sem);
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
				       struct aeon_inode *pidir, dev_t rdev,
				       u64 pi_addr, u64 de_addr)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	u64 i_addr_offset;
	u64 d_addr_offset;
	u64 p_addr_offset;

	i_addr_offset = pi_addr - (u64)sbi->virt_addr;
	d_addr_offset = de_addr - (u64)sbi->virt_addr;
	p_addr_offset = (u64)pidir - (u64)sbi->virt_addr;

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
	pi->i_pinode_addr = cpu_to_le64(p_addr_offset);
	pi->i_inode_addr = cpu_to_le64(i_addr_offset);
	pi->i_dentry_addr = cpu_to_le64(d_addr_offset);
	pi->i_size = cpu_to_le64(inode->i_size);
	pi->i_mode = cpu_to_le16(inode->i_mode);
	pi->dev.rdev =  cpu_to_le32(rdev);
	pi->i_exblocks = 0;

	aeon_init_extent_header(&pi->aeh);

	pi->persisted = 1;
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
				 struct inode *dir, u64 pi_addr, u64 de_addr,
				 u32 ino, umode_t mode, struct aeon_inode *pidir,
				 size_t size, dev_t rdev)
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

	inode_init_owner(inode, dir, mode);
	inode->i_blocks = inode->i_size = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_size = size;
	inode->i_mode = mode;
	inode->i_ino = ino;
	aeon_init_inode_flags(inode);
	//aeon_dbg("%s: allocating inode %llu @ 0x%llx\n", __func__, ino, pi_addr);

	switch (type) {
	case TYPE_CREATE:
		inode->i_op = &aeon_file_inode_operations;
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
		init_special_inode(inode, mode, rdev);
		inode->i_op = &aeon_special_inode_operations;
		break;
	default:
		aeon_dbg("Unknown new inode type %d\n", type);
		break;
	}

	si = AEON_I(inode);
	sih = &si->header;
	aeon_init_header(sb, sih, pi_addr);

	fill_new_aeon_inode(sb, sih, inode, pidir, rdev, pi_addr, de_addr);

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
	//aeon_dbg("%s: %u - %d - %d - %u\n", __func__, new_ino, sbi->cpus,
	//						cpuid, *ino);
	art->i_range_high = le32_to_cpu(i->range_high);
	art->allocated++;
	art->i_allocated++;

	//aeon_dbg("%s: Alloc ino %lu\n", __func__, *ino);
	return 0;
}

static u64 search_imem_addr(struct aeon_sb_info *sbi,
			    struct inode_map *inode_map, u32 ino)
{
	struct aeon_region_table *art = AEON_R_TABLE(inode_map);
	unsigned long blocknr;
	unsigned long internal_ino;
	int cpu_id;
	u64 addr;

	if (inode_map->im) {
		struct imem_cache *im;
		list_for_each_entry(im, &inode_map->im->imem_list, imem_list) {
			if (ino == im->ino) {
				addr = im->addr;
				list_del(&im->imem_list);
				kfree(im);
				goto found;
			}
		}
	}

	cpu_id = ino % sbi->cpus;
	if (cpu_id >= sbi->cpus)
		cpu_id -= sbi->cpus;

	internal_ino = (((ino - cpu_id) / sbi->cpus) %
			AEON_I_NUM_PER_PAGE);

	blocknr = le64_to_cpu(art->i_blocknr);
	addr = (u64)sbi->virt_addr + (blocknr << AEON_SHIFT) +
					(internal_ino << AEON_I_SHIFT);

found:
	//aeon_dbg("%s ino %u addr 0x%llx\n", __func__, ino, addr);
	return addr;
}

static int aeon_get_new_inode_address(struct super_block *sb, u32 free_ino,
				      u64 *pi_addr, int cpuid,
				      struct inode_map *inode_map)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long ret;

	ret = aeon_get_new_inode_block(sb, cpuid, free_ino);
	if (ret <= 0)
		goto err;

	*pi_addr = search_imem_addr(sbi, inode_map, free_ino);
	if (*pi_addr == 0)
		goto err;

	return 1;

err:
	aeon_err(sb, "can't alloc ino %u's inode address\n", free_ino);
	return 0;
}

u32 aeon_new_aeon_inode(struct super_block *sb, u64 *pi_addr)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map;
	int cpu_id;
	int ret;
	u32 ino = 0;
	u32 free_ino = 0;

	cpu_id = aeon_get_cpuid(sb);
	inode_map = &sbi->inode_maps[cpu_id];

	mutex_lock(&inode_map->inode_table_mutex);

	ret = aeon_alloc_unused_inode(sb, cpu_id, &free_ino, inode_map);
	if (ret) {
		aeon_err(sb, "%s: alloc inode num failed %d\n", __func__, ret);
		mutex_unlock(&inode_map->inode_table_mutex);
		return 0;
	}

	ret = aeon_get_new_inode_address(sb, free_ino, pi_addr,
					 cpu_id, inode_map);
	if (!ret) {
		aeon_err(sb, "%s: get inode addr failed %d\n", __func__, ret);
		mutex_unlock(&inode_map->inode_table_mutex);
		return 0;
	}

	mutex_unlock(&inode_map->inode_table_mutex);

	ino = free_ino;

	return ino;
}

static inline u64 aeon_get_created_inode_addr(struct super_block *sb, u32 ino)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct i_valid_list *meta;
	struct i_valid_list *mdend;
	struct i_valid_child_list *data;
	struct i_valid_child_list *ddend;
	u64 pi_addr = 0;

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
	BUG();

found:
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

	//aeon_dbgv("%s: nvmm 0x%llx\n", __func__, pi_addr);

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

	aeon_destroy_range_node_tree(sb, &sih->rb_tree);
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

void aeon_destroy_imem_cache(struct inode_map *inode_map)
{
	struct imem_cache *im;
	struct imem_cache *dend = NULL;

	list_for_each_entry_safe(im, dend, &inode_map->im->imem_list, imem_list) {
		list_del(&im->imem_list);
		kfree(im);
		im = NULL;
	}
}

static int aeon_free_inuse_inode(struct super_block *sb, unsigned long ino)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map;
	struct aeon_range_node *i = NULL;
	struct aeon_range_node *curr_node;
	struct aeon_region_table *art;
	int cpuid = ino % sbi->cpus;
	unsigned long internal_ino = ino / sbi->cpus;
	int found;
	int ret = 0;

	inode_map = &sbi->inode_maps[cpuid];
	art = AEON_R_TABLE(inode_map);

	found = aeon_search_inodetree(sbi, ino, &i);
	if (!found) {
		aeon_err(sb, "%s ERROR: ino %lu not found \n", __func__, ino);
		return -EINVAL;
	}

	if ((internal_ino == i->range_low) && (internal_ino == i->range_high)) {
		rb_erase(&i->node, &inode_map->inode_inuse_tree);
		aeon_free_inode_node(i);
		inode_map->num_range_node_inode--;
		goto block_found;
	}
	if ((internal_ino == i->range_low) && (internal_ino < i->range_high)) {
		i->range_low = internal_ino + 1;
		goto block_found;
	}
	if ((internal_ino > i->range_low) && (internal_ino == i->range_high)) {
		i->range_high = internal_ino - 1;
		goto block_found;
	}
	if ((internal_ino > i->range_low) && (internal_ino < i->range_high)) {
		curr_node = aeon_alloc_inode_node(sb);
		if (curr_node == NULL)
			goto block_found;
		curr_node->range_low = internal_ino + 1;
		curr_node->range_high = i->range_high;

		i->range_high = internal_ino - 1;

		ret = aeon_insert_inodetree(sbi, curr_node, cpuid);
		if (ret) {
			aeon_free_inode_node(curr_node);
			goto err;
		}
		inode_map->num_range_node_inode++;
		goto block_found;
	}
err:
	aeon_err(sb, "Unable to free inode %lu\n", ino);
	return ret;
block_found:
	art->freed++;
	art->i_allocated--;
	art->allocated--;
	return ret;
}

static int aeon_free_inode(struct super_block *sb, struct aeon_inode *pi,
			   struct aeon_inode_info_header *sih)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	u32 ino = le32_to_cpu(pi->aeon_ino);
	int cpuid = ino % sbi->cpus;
	struct inode_map *inode_map = &sbi->inode_maps[cpuid];
	struct imem_cache *im;
	int err = 0;

	/* TODO:
	 * improve it
	 */
	mutex_lock(&inode_map->inode_table_mutex);
	err = aeon_free_inuse_inode(sb, ino);
	if (err) {
		mutex_unlock(&inode_map->inode_table_mutex);
		return err;
	}
	im = kmalloc(sizeof(struct imem_cache), GFP_KERNEL);
	im->ino = ino;
	im->addr = sih->pi_addr;
	im->independent = 1;
	im->head = im;
	list_add(&im->imem_list, &inode_map->im->imem_list);
	mutex_unlock(&inode_map->inode_table_mutex);

	return err;
}

int aeon_free_inode_resource(struct super_block *sb, struct aeon_inode *pi,
			     struct aeon_inode_info_header *sih)
{
	int err;

	pi->deleted = 1;
	if (pi->valid)
		pi->valid = 0;

	switch (le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFREG:
		err = aeon_delete_extenttree(sb, sih);
		if (err)
			goto out;
		break;
	case S_IFDIR:
		err = aeon_delete_dir_tree(sb, sih);
		if (err)
			goto out;
		break;
	case S_IFLNK:
		aeon_dbg("Want to delete syn");
		//err = aeon_delete_symblock();
		break;
	default:
		aeon_dbg("%s: special ino %u\n",
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

void aeon_truncate_blocks(struct inode *inode, loff_t offset)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_inode *pi;
	struct aeon_extent *ae;
	struct aeon_extent_header *aeh;
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	unsigned int blkbits = inode->i_blkbits;
	unsigned long iblock = offset >> blkbits;
	unsigned long new_num_blocks ;
	unsigned long new_blocknr = 0;
	unsigned long off;
	unsigned long old_num_blocks;
	loff_t old_size = inode->i_size;
	int allocated;
	int entries;
	int index = 0;
	int err;
	int length;

#ifdef USE_RB
	pi = aeon_get_inode(sb, sih);
	aeh = aeon_get_extent_header(pi);
	mutex_lock(&sih->truncate_mutex);

	ae = aeon_search_extent(sb, sih, iblock);
	if (!ae)
		goto expand;
	entries = le16_to_cpu(aeh->eh_entries);

	index = le16_to_cpu(ae->ex_index);
	off = le32_to_cpu(ae->ex_offset);
	length = le32_to_cpu(ae->ex_length);
	if (old_size < offset)
		ae->ex_length = cpu_to_le16(off + length - iblock);

	aeh->eh_entries = cpu_to_le16(++index);
	entries = entries - index - 1;
	err = aeon_cutoff_extenttree(sb, sih, pi, entries, index);
	if (err)
		aeon_err(sb, "%s\n", __func__);
	mutex_unlock(&sih->truncate_mutex);
	return;
#else
	u64 addr;
	unsigned long num_blocks = 0;

	pi = aeon_get_inode(sb, sih);
	aeh = aeon_get_extent_header(pi);
	mutex_lock(&sih->truncate_mutex);

	write_lock(&sih->i_meta_lock);
	entries = le16_to_cpu(aeh->eh_entries);
	write_unlock(&sih->i_meta_lock);
	while(entries > 0) {
		addr = aeon_pull_extent_addr(sb, sih, index);
		ae = (struct aeon_extent *)addr;

		write_lock(&sih->i_meta_lock);
		num_blocks += le16_to_cpu(ae->ex_length);
		off = le32_to_cpu(ae->ex_offset);
		length = le16_to_cpu(ae->ex_length);
		write_unlock(&sih->i_meta_lock);
		if (off <= iblock && iblock < off + length) {
			if (old_size < offset) {
				write_lock(&sih->i_meta_lock);
				ae->ex_length = cpu_to_le16(off + length - iblock);
				write_unlock(&sih->i_meta_lock);
			}
			write_lock(&sih->i_meta_lock);
			aeh->eh_entries = cpu_to_le16(++index);
			write_unlock(&sih->i_meta_lock);
			addr = aeon_pull_extent_addr(sb, sih, index);
			ae = (struct aeon_extent *)addr;
			err = aeon_cutoff_extenttree(sb, sih, pi, --entries, index);
			if (err)
				aeon_err(sb, "%s\n", __func__);
			mutex_unlock(&sih->truncate_mutex);
			return;
		}
		index++;
		entries--;
	}
#endif
expand:

	old_num_blocks = old_size >> blkbits;
	new_num_blocks = iblock - old_num_blocks;
	if (!new_num_blocks)
		new_num_blocks = 1;

	allocated = aeon_new_data_blocks(sb, sih, &new_blocknr,
					 iblock, new_num_blocks, ANY_CPU);
	if (allocated <= 0) {
		mutex_unlock(&sih->truncate_mutex);
		return;
	}

	err = aeon_update_extent(sb, inode, new_blocknr, iblock, allocated);
	if (err) {
		aeon_err(sb, "failed to update extent\n");
		mutex_unlock(&sih->truncate_mutex);
		return;
	}

	clean_bdev_aliases(sb->s_bdev, new_blocknr, allocated);
	err = sb_issue_zeroout(sb, new_blocknr, allocated, GFP_NOFS);
	if (err)
		aeon_err(sb, "%s: ERROR\n", __func__);
	mutex_unlock(&sih->truncate_mutex);
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
