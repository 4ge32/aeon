#include <linux/fs.h>

#include "aeon.h"
#include "super.h"
#include "inode.h"
#include "balloc.h"

struct aeon_dentry *aeon_find_dentry(struct super_block *sb,
	struct aeon_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len)
{
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_dentry *direntry = NULL;
	struct aeon_range_node *ret_node = NULL;
	unsigned long hash;
	int found = 0;

	hash = BKDRHash(name, name_len);

	found = aeon_find_range_node(&sih->rb_tree, hash,
				NODE_DIR, &ret_node);
	if (found == 1 && hash == ret_node->hash)
		direntry = ret_node->direntry;

	return direntry;
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

struct inode *aeon_new_vfs_inode(enum aeon_new_inode_type type,
	struct inode *dir, u64 pi_addr, u64 ino, umode_t mode,
	size_t size, dev_t rdev, const struct qstr *qstr)
{
	struct super_block *sb;
	struct aeon_sb_info *sbi;
	struct inode *inode;
	struct aeon_inode *pi;
	struct aeon_inode_info *si;
	struct aeon_inode_info_header *sih = NULL;
	int err;

	aeon_dbg("%s: START\n", __func__);
	sb = dir->i_sb;
	sbi = (struct aeon_sb_info *)sb->s_fs_info;
	inode = new_inode(sb);
	if (!inode) {
		err = -ENOMEM;
		goto out;
	}

	aeon_dbg("%s: new inode\n", __func__);
	inode_init_owner(inode, dir, mode);
	inode->i_blocks = inode->i_size = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	//inode->i_generation = atomic_add_return(1, &sbi->next_generation);
	inode->i_size = size;

	//diri = aeon_get_inode(sb, dir);
	//if (diri == NULL) {
	//	aeon_err(sb, "%s ERROR\n", __func__);
	//	err = -EACCES;
	//	goto out1;
	//}
	//aeon_dbg("%s: dir inode - %llu\n", __func__, diri->aeon_ino);

	//pi = (struct aeon_inode *)aeon_get_block(sb, pi_addr);
	aeon_dbg("%s: allocating inode %llu @ 0x%llx\n", __func__, ino, pi_addr);

	/* chosen inode is in ino */
	inode->i_ino = ino;

	switch (type) {
	case TYPE_CREATE:
		//inode->i_op = &aeon_file_inode_operations;
		//inode->i_fop = &aeon_dax_file_operations;
		//inode->i_mapping->a_ops = &aeon_aops_dax;
		break;
	case TYPE_MKDIR:
		inode->i_op = &aeon_dir_inode_operations;
		//inode->i_fop = &aeon_dir_operations;
		//inode->i_mapping->a_ops = &aeon_aops_dax;
		set_nlink(inode, 2);
		break;
	default:
		aeon_dbg("Unknown new inode type %d\n", type);
		break;
	}

	//err = aeon_get_inode_address(sb, ino, 0, &pi_addr, 0, 0);
	//if (err) {
	//	aeon_dbg("%s: get inode address failed %d\n", __func__, ret);
	//	goto out1;
	//}
	aeon_dbg("%s: pi_addr 0x%llx\n", __func__, pi_addr);
	pi = (struct aeon_inode *)pi_addr;
	pi->i_mode = inode->i_mode;
	pi->aeon_ino = inode->i_ino;

	si = AEON_I(inode);
	sih = &si->header;
	aeon_init_header(sb, sih, inode->i_mode);
	sih->pi_addr = pi_addr;
	sih->ino = ino;

	aeon_dbg("%s: FINISH\n", __func__);
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
	unsigned long next_range_low;
	unsigned long new_ino;
	unsigned long MAX_INODE = 1UL << 31;

	inode_map = &sbi->inode_maps[cpuid];
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

	*ino = new_ino * sbi->cpus + cpuid;
	sbi->s_inodes_used_count++;
	inode_map->allocated++;

	aeon_dbg("%s: Alloc ino %lu\n", __func__, *ino);
	return 0;
}

u64 aeon_new_aeon_inode(struct super_block *sb, u64 *pi_addr)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map;
	int map_id;
	int ret;
	u64 ino = 0;
	unsigned long free_ino = 0;

	map_id = sbi->map_id;
	sbi->map_id = (sbi->map_id + 1) % sbi->cpus;
	sbi->map_id = 0;

	inode_map = &sbi->inode_maps[map_id];

	mutex_lock(&inode_map->inode_table_mutex);
	ret = aeon_alloc_unused_inode(sb, map_id, &free_ino);
	if (ret) {
		aeon_err(sb, "%s: alloc inode number failed %d\n", __func__, ret);
		mutex_unlock(&inode_map->inode_table_mutex);
		return 0;
	}

	ret = aeon_get_inode_address(sb, free_ino, pi_addr);
	if (ret) {
		aeon_dbg("%s: get inode address failed %d\n", __func__, ret);
		mutex_unlock(&inode_map->inode_table_mutex);
		return 0;
	}

	aeon_dbg("%s: ?\n", __func__);
	mutex_unlock(&inode_map->inode_table_mutex);

	ino = free_ino;

	aeon_dbg("%s: free_ino is %llu\n", __func__, ino);
	return ino;
}

inline int aeon_insert_inodetree(struct aeon_sb_info *sbi, struct aeon_range_node *new_node, int cpu)
{
	struct rb_root *tree;
	int ret;

	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	ret = aeon_insert_range_node(tree, new_node, NODE_INODE);
	if (ret)
		aeon_dbg("ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

int aeon_init_inode_inuse_list(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_range_node *range_node;
	struct inode_map *inode_map;
	unsigned long range_high;
	int i;
	int ret;

	aeon_dbg("%s: START\n", __func__);
	sbi->s_inodes_used_count = AEON_INODE_START;

	range_high = AEON_INODE_START / sbi->cpus;
	if (AEON_INODE_START % sbi->cpus)
		range_high++;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		aeon_dbg("%s: alloc_inode_node\n", __func__);
		range_node = aeon_alloc_inode_node(sb);
		if (range_node == NULL)
			return -ENOMEM;

		range_node->range_low = 0;
		range_node->range_high = range_high;
		aeon_dbg("%s: insert_inodetree\n", __func__);
		ret = aeon_insert_inodetree(sbi, range_node, i);
		if (ret) {
			aeon_err(sb, "%s failed\n", __func__);
			aeon_free_inode_node(range_node);
			return ret;
		}
		inode_map->num_range_node_inode = 1;
		inode_map->first_inode_range = range_node;
	}

	aeon_dbg("%s: FINISH\n", __func__);
	return 0;
}

int aeon_get_inode_address(struct super_block *sb, u64 ino, u64 *pi_addr)
{
	*pi_addr = aeon_get_reserved_inode_addr(sb, ino);

	return 0;
}

int aeon_rebuild_inode(struct super_block *sb, struct aeon_inode_info *si,
		       u64 ino, u64 pi_addr, int rebuild_dir)
{
	struct aeon_inode_info_header *sih  = &si->header;
	aeon_init_header(sb, sih, 0755);
	sih->pi = (struct aeon_inode *)pi_addr;

	return 0;
}

static void aeon_set_inode_flags(struct inode *inode, struct aeon_inode *pi, unsigned int flags)
{
	inode->i_flags |= S_DAX;
}

/* copy persistent state to struct inode */
static int aeon_read_inode(struct super_block *sb, struct inode *inode, u64 pi_addr)
{
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode *pi;
	struct aeon_inode_info_header *sih = &si->header;
	int ret = -EIO;
	unsigned long ino;

	aeon_dbg("%s: pi_addr 0x%llx\n", __func__, pi_addr);

	pi = sih->pi;
	aeon_dbg("%s: %p\n", __func__, pi);

	inode->i_mode = pi->i_mode;
	i_uid_write(inode, le32_to_cpu(pi->i_uid));
	i_gid_write(inode, le32_to_cpu(pi->i_gid));
	aeon_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));
	ino = le32_to_cpu(pi->aeon_ino);
	aeon_dbg("%s: ino - %lu\n", __func__, ino);

	if (inode->i_mode == 0 || pi->deleted == 1) {
		ret = -ESTALE;
		goto bad_inode;
	}

	inode->i_blocks = sih->i_blocks;
	//inode->i_mapping->a_ops = &aeon_aops_dax;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		//inode->i_op = &aeon_file_inode_operations;
		//inode->i_fop = &aeon_dax_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &aeon_dir_inode_operations;
		//inode->i_fop = &aeon_dir_operations;
		break;
	//case S_IFLNK:
	//	inode->i_op = &aeon_symlink_inode_operations;
	//	break;
	//default:
	//	inode->i_op = &aeon_special_inode_operations;
	//	init_special_inode(inode, inode->i_mode,
	//			   le32_to_cpu(pi->dev.rdev));
		break;
	}

	inode->i_size = le64_to_cpu(sih->i_size);
	inode->i_atime.tv_sec = (__s32)le32_to_cpu(pi->i_atime);
	inode->i_ctime.tv_sec = (__s32)le32_to_cpu(pi->i_ctime);
	inode->i_mtime.tv_sec = (__s32)le32_to_cpu(pi->i_mtime);
	inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
					 inode->i_ctime.tv_nsec = 0;
	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	aeon_dbg("%s: LAST\n", __func__);

	return 0;

bad_inode:
	make_bad_inode(inode);
	return ret;
}

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

	err = aeon_get_inode_address(sb, ino, &pi_addr);
	if (err) {
		aeon_err(sb, "%s: get inode address failed %d\n", __func__, err);
		goto fail;
	}
	aeon_dbg("%s: nvmm 0x%llx\n", __func__, pi_addr);

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
		aeon_dbg("%s: failed to read inode %lu\n", __func__, ino);
		goto fail;
	}

	inode->i_sb = sb;

	unlock_new_inode(inode);
	return inode;
fail:
	iget_failed(inode);
	return ERR_PTR(err);
}
