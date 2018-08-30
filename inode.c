#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/iomap.h>
#include <linux/posix_acl.h>
#include <linux/mm.h>
#include <linux/buffer_head.h>

#include "aeon.h"

#define AEON_BLOCK_TYPE_MAX 1
unsigned int blk_type_to_shift[AEON_BLOCK_TYPE_MAX] = {12};
uint32_t blk_type_to_size[AEON_BLOCK_TYPE_MAX] = {0x1000};


static inline int aeon_insert_inodetree(struct aeon_sb_info *sbi, struct aeon_range_node *new_node, int cpu)
{
	struct rb_root *tree;
	int ret;

	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	ret = aeon_insert_range_node(tree, new_node, NODE_INODE);
	if (ret)
		aeon_err(sbi->sb, "ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

static inline int aeon_search_inodetree(struct aeon_sb_info *sbi, unsigned long ino, struct aeon_range_node **ret_node)
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

ino_t aeon_inode_by_name(struct inode *dir, struct qstr *entry)
{
	struct super_block *sb = dir->i_sb;
	struct aeon_dentry *direntry;

	direntry = aeon_find_dentry(sb, NULL, dir, entry->name, entry->len);

	if (direntry == NULL)
		return 0;

	return direntry->ino;
}

static void fill_new_aeon_inode(u64 pi_addr, struct inode *inode)
{
	struct aeon_inode *pi = (struct aeon_inode *)pi_addr;

	pi->deleted = 0;
	pi->i_new = 1;
	pi->i_links_count = cpu_to_le16(inode->i_nlink);
	pi->i_mtime = pi->i_atime = pi->i_ctime =
		pi->i_create_time = cpu_to_le32(current_time(inode).tv_sec);
	pi->i_uid = cpu_to_le32(i_uid_read(inode));
	pi->i_gid = cpu_to_le32(i_gid_read(inode));
	pi->aeon_ino = le32_to_cpu(inode->i_ino);
	pi->i_block = 0;
	pi->i_blocks = 0;
	pi->i_internal_allocated = 0;
	pi->dentry_map_block = 0;
	pi->i_size = cpu_to_le64(inode->i_size);
	pi->i_mode = cpu_to_le16(inode->i_mode);

	pi->valid = 1;
}

struct inode *aeon_new_vfs_inode(enum aeon_new_inode_type type,
	struct inode *dir, u64 pi_addr, u64 ino, umode_t mode,
	size_t size, dev_t rdev, const struct qstr *qstr)
{
	struct super_block *sb;
	struct aeon_sb_info *sbi;
	struct inode *inode;
	struct aeon_inode_info *si;
	struct aeon_inode_info_header *sih = NULL;
	int err;

	sb = dir->i_sb;
	sbi = (struct aeon_sb_info *)sb->s_fs_info;
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

	//aeon_dbg("%s: allocating inode %llu @ 0x%llx\n", __func__, ino, pi_addr);

	/* chosen inode is in ino */
	inode->i_ino = ino;

	switch (type) {
	case TYPE_CREATE:
		inode->i_op = &aeon_file_inode_operations;
		inode->i_fop = &aeon_dax_file_operations;
		//inode->i_mapping->a_ops = &aeon_aops_dax;
		break;
	case TYPE_MKDIR:
		inode->i_op = &aeon_dir_inode_operations;
		inode->i_fop = &aeon_dir_operations;
		//inode->i_mapping->a_ops = &aeon_aops_dax;
		set_nlink(inode, 2);
		break;
	case TYPE_SYMLINK:
		inode->i_op = &aeon_symlink_inode_operations;
		break;
	default:
		aeon_dbg("Unknown new inode type %d\n", type);
		break;
	}

	fill_new_aeon_inode(pi_addr, inode);

	si = AEON_I(inode);
	sih = &si->header;
	aeon_init_header(sb, sih, inode->i_mode);
	sih->pi_addr = pi_addr;
	sih->ino = ino;

	return inode;
out:
	make_bad_inode(inode);
	iput(inode);
	return ERR_PTR(err);
}

static int aeon_alloc_unused_inode(struct super_block *sb, int cpuid, unsigned long *ino)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map;
	struct aeon_range_node *i, *next_i;
	struct rb_node *temp, *next;
	struct aeon_region_table *art;
	unsigned long next_range_low;
	unsigned long new_ino;
	unsigned long MAX_INODE = 1UL << 31;

	inode_map = &sbi->inode_maps[cpuid];
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

	*ino = AEON_INODE_START + (new_ino - 2) * sbi->cpus + cpuid;
	//aeon_dbgv("%s: %lu - %d - %d\n", __func__, new_ino, sbi->cpus, cpuid);
	sbi->s_inodes_used_count++;
	art->i_range_high = le32_to_cpu(i->range_high);
	art->allocated++;

	//aeon_dbgv("%s: Alloc ino %lu\n", __func__, *ino);
	return 0;
}

static int aeon_get_new_inode_address(struct super_block *sb, u64 free_ino, u64 *pi_addr, int cpuid)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map = &sbi->inode_maps[cpuid];

	if (!aeon_get_new_inode_block(sb, cpuid, free_ino))
		goto err;

	*pi_addr = search_imem_cache(sbi, inode_map, free_ino);
	if (*pi_addr == 0)
		goto err;

	//aeon_dbgv("%s: cpu-id %d --- %llx\n", __func__, cpuid, *pi_addr);

	return 1;

err:
	aeon_err(sb, "can't alloc inode address\n");
	return 0;
}

u64 aeon_new_aeon_inode(struct super_block *sb, u64 *pi_addr)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_super_block *aeon_sb = aeon_get_super(sb);
	struct inode_map *inode_map;
	int map_id;
	int ret;
	u64 ino = 0;
	unsigned long free_ino = 0;

	map_id = aeon_sb->s_map_id;
	aeon_sb->s_map_id = (aeon_sb->s_map_id + 1) % sbi->cpus;

	inode_map = &sbi->inode_maps[map_id];

	mutex_lock(&inode_map->inode_table_mutex);

	ret = aeon_alloc_unused_inode(sb, map_id, &free_ino);
	if (ret) {
		aeon_err(sb, "%s: alloc inode number failed %d\n", __func__, ret);
		mutex_unlock(&inode_map->inode_table_mutex);
		return 0;
	}

	ret = aeon_get_new_inode_address(sb, free_ino, pi_addr, map_id);
	if (!ret) {
		aeon_err(sb, "%s: get inode address failed %d\n", __func__, ret);
		mutex_unlock(&inode_map->inode_table_mutex);
		return 0;
	}

	mutex_unlock(&inode_map->inode_table_mutex);

	ino = free_ino;

	//aeon_dbgv("%s: free_ino is %llu\n", __func__, ino);
	return ino;
}

static inline u64 aeon_get_created_inode_addr(struct super_block *sb, u64 ino)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	int num_cpu = sbi->cpus;
	int cpu_id = (ino - AEON_INODE_START) % num_cpu;
	struct inode_map *inode_map = &sbi->inode_maps[cpu_id];
	struct i_valid_list *data;
	struct i_valid_list *dend = NULL;
	u64 pi_addr = 0;

	list_for_each_entry_safe(data, dend, &inode_map->ivl->i_valid_list, i_valid_list) {
		if (ino == data->ino) {
			pi_addr = data->addr;
			list_del(&data->i_valid_list);
			kfree((void *)data);
			goto found;
		}
	}

	aeon_err(sb, "not found corresponding inode\n");
	BUG_ON(1);

found:
	return pi_addr;
}

static inline u64 aeon_get_reserved_inode_addr(struct super_block *sb, u64 ino)
{
	u64 addr = 0;

	if (ino == AEON_ROOT_INO)
		addr =  _aeon_get_reserved_inode_addr(sb, ino);
	else
		addr = aeon_get_created_inode_addr(sb, ino);

	return addr;
}

static int aeon_rebuild_inode(struct super_block *sb, struct aeon_inode_info *si,
			      u64 ino, u64 pi_addr, int rebuild_dir)
{
	struct aeon_inode_info_header *sih  = &si->header;
	struct aeon_inode *pi = (struct aeon_inode *)pi_addr;
	aeon_init_header(sb, sih, 0755);

	sih->pi_addr = pi_addr;
	sih->ino = ino;

	if (pi->i_new)
		goto end;

	switch (le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFDIR:
		aeon_rebuild_dir_inode_tree(sb, pi, pi_addr, sih);
		break;
	default:
		break;
	}

end:
	return 0;
}

static void aeon_set_inode_flags(struct inode *inode, struct aeon_inode *pi, unsigned int flags)
{
	inode->i_flags |= S_DAX;
}

/* copy persistent state to struct inode */
static int aeon_read_inode(struct super_block *sb, struct inode *inode, u64 pi_addr)
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
	//inode->i_mapping->a_ops = &aeon_aops_dax;

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
	//	inode->i_op = &aeon_special_inode_operations;
	//	init_special_inode(inode, inode->i_mode,
	//			   le32_to_cpu(pi->dev.rdev));
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
struct inode *aeon_iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode;
	struct aeon_inode_info *si;
	u64 pi_addr = 0;
	int err;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	si = AEON_I(inode);

	pi_addr = aeon_get_reserved_inode_addr(sb, ino);

	//aeon_dbgv("%s: nvmm 0x%llx\n", __func__, pi_addr);

	if (pi_addr == 0) {
		aeon_err(sb, "%s: failed to get pi_addr for inode %lu\n", __func__, ino);
		err = -EACCES;
		goto fail;
	}

	err = aeon_rebuild_inode(sb, si, ino, pi_addr, 1);
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

static unsigned long aeon_get_last_blocknr(struct super_block *sb, struct aeon_inode_info_header *sih)
{
	unsigned long last_blocknr;
	unsigned int btype;
	unsigned int data_bits;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	int ret;
	return 0;

	if (ret) {
		//aeon_dbgv("%s: read pi @ 0x%lx failed\n",
		//		__func__, sih->pi_addr);
		btype = 0;
	} else {
		btype = sih->i_blk_type;
	}

	data_bits = blk_type_to_shift[btype];

	if (pi->i_size == 0)
		last_blocknr = 0;
	else
		last_blocknr = (pi->i_size - 1) >> data_bits;

	return last_blocknr;
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

	if (S_ISREG(pi->i_mode)) {
		//last_blocknr = nova_get_last_blocknr(sb, sih);
		//freed = nova_delete_file_tree(sb, sih, 0,
		//			last_blocknr, false, false, 0);
	} else {
		aeon_delete_dir_tree(sb, sih);
		freed = 1;
	}

	return freed;
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
	int ret;

	//aeon_dbgv("Free inuse ino: %lu\n", ino);
	inode_map = &sbi->inode_maps[cpuid];
	art = AEON_R_TABLE(inode_map);

	mutex_lock(&inode_map->inode_table_mutex);
	found = aeon_search_inodetree(sbi, ino, &i);
	if (!found) {
		aeon_err(sb, "%s ERROR: ino %lu not found \n", __func__, ino);
		mutex_unlock(&inode_map->inode_table_mutex);
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
	mutex_unlock(&inode_map->inode_table_mutex);
	return ret;
block_found:
	sbi->s_inodes_used_count--;
	art->freed++;
	mutex_unlock(&inode_map->inode_table_mutex);
	return ret;
}

static int aeon_free_inode(struct super_block *sb, struct aeon_inode *pi,
			   struct aeon_inode_info_header *sih)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	ino_t ino = le32_to_cpu(pi->aeon_ino);
	int cpuid = ino % sbi->cpus;
	struct inode_map *inode_map = &sbi->inode_maps[cpuid];
	struct imem_cache *im;
	int err = 0;

	/* TODO:
	 * improve it
	 */
	err = aeon_free_inuse_inode(sb, ino);
	im = kmalloc(sizeof(struct imem_cache), GFP_KERNEL);
	im->ino = sih->ino;
	im->addr = sih->pi_addr;
	im->independent = 1;
	im->head = im;
	list_add(&im->imem_list, &inode_map->im->imem_list);

	return err;
}

int aeon_free_inode_resource(struct super_block *sb, struct aeon_inode *pi,
			     struct aeon_inode_info_header *sih)
{
	unsigned long last_blocknr;
	int ret = 0;

	aeon_memunlock_inode(sb, pi);
	pi->deleted = 1;

	if (pi->valid) {
		aeon_dbgv("%s: inode %lu still valid\n",
				__func__, sih->ino);
		pi->valid = 0;
	}
	aeon_memunlock_inode(sb, pi);

	switch (le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFREG:
		last_blocknr = aeon_get_last_blocknr(sb, sih);
		aeon_dbgv("%s: file ino %lu\n", __func__, sih->ino);
		//freed = aeon_delete_file_tree(sb, sih, 0,
		//			last_blocknr, true, true);
		break;
	case S_IFDIR:
		aeon_dbgv("%s: dir ino %lu\n", __func__, sih->ino);
		aeon_delete_dir_tree(sb, sih);
		break;
	case S_IFLNK:
		/* Log will be freed later */
		aeon_dbgv("%s: symlink ino %lu\n",
				__func__, sih->ino);
		//freed = aeon_delete_file_tree(sb, sih, 0, 0,
		//				true, true);
		break;
	default:
		aeon_dbgv("%s: special ino %lu\n",
				__func__, sih->ino);
		break;
	}

	ret = aeon_free_inode(sb, pi, sih);
	if (ret)
		aeon_err(sb, "%s: free inode %lu failed\n", __func__, pi->aeon_ino);

	return ret;
}

static void aeon_setattr_to_pmem(const struct inode *inode, struct aeon_inode *pi,
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

int aeon_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = d_inode(dentry);
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	//loff_t oldsize = inode->i_size;
	unsigned int ia_valid = iattr->ia_valid;
	unsigned int attr_mask = attr_mask;
	int err = 0;

	if (!pi) {
		err = -EACCES;
		goto out;
	}

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

	if (iattr->ia_valid & ATTR_SIZE && iattr->ia_size != inode->i_size)
		return -EPERM;

	return 0;

out:
	return 0;
}
