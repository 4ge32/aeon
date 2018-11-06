#include <linux/fs.h>
#include <linux/slab.h>

#include "aeon.h"

#define IF2DT(sif) (((sif) & S_IFMT) >> 12)


int aeon_insert_dir_tree(struct super_block *sb,
			 struct aeon_inode_info_header *sih,
			 const char *name, int namelen,
			 struct aeon_dentry *direntry)
{
	struct aeon_range_node *node = NULL;
	unsigned long hash;
	int ret;

	hash = BKDRHash(name, namelen);

	node  = aeon_alloc_dir_node(sb);
	if (!node)
		return -ENOMEM;
	node->hash = hash;
	node->direntry = direntry;

	ret = aeon_insert_range_node(&sih->rb_tree, node, NODE_DIR);
	if (ret) {
		aeon_free_dir_node(node);
		aeon_err(sb, "%s: %d - %s\n", __func__, ret, name);
	}

	return ret;
}

static int aeon_remove_dir_tree(struct super_block *sb,
				struct aeon_inode_info_header *sih,
				const char *name, int namelen)
{
	struct aeon_dentry *entry;
	struct aeon_range_node *ret_node = NULL;
	unsigned long hash;
	bool found = false;

	hash = BKDRHash(name, namelen);
	found = aeon_find_range_node(&sih->rb_tree, hash, NODE_DIR, &ret_node);
	if (!found || (hash != ret_node->hash)) {
		aeon_err(sb, "%s target not found: %s, length %d, hash %lu\n",
			 __func__, name,
			 namelen, hash);
		return -EINVAL;
	}

	entry = ret_node->direntry;
	rb_erase(&ret_node->node, &sih->rb_tree);
	aeon_free_dir_node(ret_node);

	return 0;
}

/*
 * Filesystem already knows whether pi is valid or not.
 */
int aeon_get_dentry_address(struct super_block *sb,
			    struct aeon_inode *pi, u64 *de_addr)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_dentry *de;
	unsigned long internal;
	unsigned long blocknr;
	unsigned long boundary;

	if (pi->aeon_ino == cpu_to_le32(AEON_ROOT_INO))
		return 0;

	internal = le32_to_cpu(pi->i_d_internal_off);
	blocknr = le64_to_cpu(pi->i_dentry_block);
	boundary = sbi->last_blocknr;

	if (blocknr > boundary) {
		aeon_dbg("up to %lu but blocknr %lu\n", boundary, blocknr);
		return -ENOENT;
	}

	if (internal == 0 && blocknr == 0) {
		aeon_dbg("%s illegal block\n", __func__);
		return -ENOENT;
	}

	*de_addr = (u64)sbi->virt_addr + (blocknr << AEON_SHIFT) +
					(internal << AEON_D_SHIFT);

	de = (struct aeon_dentry *)(*de_addr);
	if (pi->aeon_ino != de->ino) {
		u32 pi_ino = le32_to_cpu(pi->aeon_ino);
		u32 de_ino = le32_to_cpu(de->ino);

		aeon_err(sb, "%s: pi_ino %u de_ino %u blocknr %lu, internal %lu\n"
			 , __func__, pi_ino, de_ino, blocknr, internal);
		return -EINVAL;
	}

	return 0;
}

struct aeon_dentry *aeon_dotdot(struct super_block *sb,
				struct dentry *dentry)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct dentry *parent = dentry->d_parent;
	struct inode *inode = d_inode(parent);
	struct aeon_dentry_map *de_map;
	struct aeon_dentry *de;
	unsigned long dotdot_block;

	de_map = aeon_get_dentry_map(sb, &AEON_I(inode)->header);
	if (!de_map)
		return NULL;

	dotdot_block = le64_to_cpu(de_map->block_dentry[0]);
	de = (struct aeon_dentry *)((u64)sbi->virt_addr +
				    (dotdot_block << AEON_SHIFT) +
				    (1 << AEON_D_SHIFT));
	return de;
}

void aeon_delete_dir_tree(struct super_block *sb,
			  struct aeon_inode_info_header *sih)
{
	aeon_destroy_range_node_tree(sb, &sih->rb_tree);
}

static void aeon_register_dentry_to_map(struct aeon_dentry_map *de_map,
					unsigned long d_blocknr)
{
	de_map->num_latest_dentry++;
	de_map->block_dentry[le64_to_cpu(de_map->num_latest_dentry)] = d_blocknr;
	de_map->num_internal_dentries = 1;
}

static struct aeon_dentry *aeon_get_internal_dentry(struct super_block *sb,
						    struct aeon_dentry_map *de_map,
						    u64 *blocknr)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned int latest_entry;
	unsigned int internal_entry;
	unsigned long head_addr;
	unsigned int internal_offset;

	latest_entry = le64_to_cpu(de_map->num_latest_dentry);
	internal_entry = le64_to_cpu(de_map->num_internal_dentries);
	head_addr = le64_to_cpu(de_map->block_dentry[latest_entry]) << AEON_SHIFT;
	internal_offset = internal_entry << AEON_D_SHIFT;

	*blocknr = head_addr >> AEON_SHIFT;

	return (struct aeon_dentry *)((u64)sbi->virt_addr +
				      head_addr + internal_offset);
}

static int isInvalidSpace(struct aeon_dentry_info *de_info)
{
	struct aeon_dentry_invalid *di = de_info->di;

	if (list_empty(&di->invalid_list))
		return 0;
	return 1;
}

static struct aeon_dentry *aeon_reuse_space_for_dentry(struct super_block *sb,
						       struct aeon_dentry_map *de_map,
						       struct aeon_dentry_info *de_info,
						       u64 *blocknr)
{
	struct aeon_dentry *de;
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_dentry_invalid *adi = list_first_entry(&de_info->di->invalid_list,
							   struct aeon_dentry_invalid,
							   invalid_list);
	unsigned int latest_entry = adi->global;
	unsigned int internal_entry = adi->internal;
	unsigned long head_addr = le64_to_cpu(de_map->block_dentry[latest_entry]) << AEON_SHIFT;
	unsigned int internal_offset = internal_entry << AEON_D_SHIFT;

	de = (struct aeon_dentry *)((u64)sbi->virt_addr +
				    head_addr + internal_offset);
	de->internal_offset = cpu_to_le32(adi->internal);
	de->global_offset = adi->global;
	if (internal_entry == 0 && latest_entry == 0)
		BUG();
	*blocknr = head_addr >> AEON_SHIFT;

	list_del(&adi->invalid_list);
	kfree(adi);
	adi = NULL;

	return de;
}

static int aeon_init_dentry_map(struct super_block *sb,
				struct aeon_inode *pidir,
				struct aeon_inode_info_header *sih)
{
	struct aeon_dentry_info *de_info;
	struct aeon_dentry_map *de_map;
	struct aeon_dentry_invalid *adi;

	de_info = kzalloc(sizeof(struct aeon_dentry_info), GFP_KERNEL);
	if (!de_info)
		return -ENOMEM;

	adi = kzalloc(sizeof(struct aeon_dentry_invalid), GFP_KERNEL);
	if (!adi) {
		kfree(de_info);
		de_info = NULL;
		return -ENOMEM;
	}

	de_map = &de_info->de_map;
	de_map->num_dentries = 0;
	de_map->num_latest_dentry = 0;
	de_map->num_internal_dentries = AEON_INTERNAL_ENTRY;

	de_info->di = adi;
	sih->de_info = de_info;

	INIT_LIST_HEAD(&de_info->di->invalid_list);

	pidir->i_new = 0;

	return 0;
}

static int aeon_init_dentry(struct super_block *sb, struct aeon_inode *pidir,
			    struct aeon_dentry_info *de_info, u32 ino)
{
	struct aeon_dentry *direntry;
	struct aeon_dentry_map *de_map = &de_info->de_map;
	unsigned long blocknr;
	u64 pi_addr = 0;

	blocknr = aeon_get_new_dentry_block(sb, &pi_addr, ANY_CPU);
	if (blocknr == 0)
		return -ENOSPC;

	direntry = (struct aeon_dentry *)pi_addr;
	strncpy(direntry->name, ".\0", 2);
	direntry->internal_offset = 0;
	direntry->global_offset = 0;
	direntry->name_len = 2;
	direntry->ino = cpu_to_le32(pidir->aeon_ino);
	direntry->valid = 1;
	direntry->persisted = 1;
	aeon_update_dentry_csum(direntry);

	direntry = (struct aeon_dentry *)(pi_addr + (1 << AEON_D_SHIFT));
	strncpy(direntry->name, "..\0", 3);
	direntry->internal_offset = 1;
	direntry->global_offset = 0;
	direntry->name_len = 3;
	direntry->ino = cpu_to_le32(pidir->parent_ino);
	direntry->persisted = 1;
	direntry->valid = 1;
	aeon_update_dentry_csum(direntry);

	de_map->num_internal_dentries = 2;
	de_map->num_dentries = 2;
	de_map->block_dentry[0] = blocknr;

	return 0;
}

static struct aeon_dentry *aeon_alloc_new_dentry_block(struct super_block *sb,
						       u64 *d_blocknr)
{
	struct aeon_dentry *direntry;
	u64 pi_addr = 0;

	*d_blocknr = aeon_get_new_dentry_block(sb, &pi_addr, ANY_CPU);
	if (*d_blocknr == 0)
		return ERR_PTR(-ENOSPC);

	direntry = (struct aeon_dentry *)pi_addr;

	return direntry;
}

static u64 aeon_get_dentry_block(struct super_block *sb,
				 struct aeon_dentry_info *de_info,
				 struct aeon_dentry **direntry)
{
	struct aeon_dentry_map *de_map = &de_info->de_map;
	u64 blocknr = 0;

	if(!isInvalidSpace(de_info)) {
		if (de_map->num_internal_dentries == AEON_INTERNAL_ENTRY) {
			*direntry = aeon_alloc_new_dentry_block(sb, &blocknr);
			if (IS_ERR(*direntry))
				return -ENOSPC;
			aeon_register_dentry_to_map(de_map, blocknr);
			(*direntry)->internal_offset = 0;
			(*direntry)->global_offset = cpu_to_le32((de_map->num_latest_dentry));
		} else {
			*direntry = aeon_get_internal_dentry(sb, de_map, &blocknr);
			(*direntry)->internal_offset = cpu_to_le32(de_map->num_internal_dentries);
			(*direntry)->global_offset = cpu_to_le32(de_map->num_latest_dentry);

			de_map->num_internal_dentries++;
		}

	} else
		*direntry = aeon_reuse_space_for_dentry(sb, de_map, de_info, &blocknr);

	(*direntry)->valid = 1;
	de_map->num_dentries++;

	return blocknr;
}

static void aeon_fill_dentry_data(struct aeon_dentry *de, u32 ino,
				  u64 i_blocknr, const char *name, int namelen)
{
	de->name_len = le32_to_cpu(namelen);
	de->ino = cpu_to_le32(ino);
	de->i_blocknr = cpu_to_le64(i_blocknr);
	strscpy(de->name, name, namelen + 1);
	de->valid = 1;
	de->persisted = 1;
	aeon_update_dentry_csum(de);
}

static void aeon_release_dentry_block(struct aeon_dentry *de)
{
	de->valid = 0;
	aeon_update_dentry_csum(de);
}

int aeon_add_dentry(struct dentry *dentry, u32 ino, u64 i_blocknr,
		    u64 *d_blocknr, int inc_link)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pidir;
	struct aeon_dentry *new_direntry = NULL;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	int err;

	if (namelen == 0 || namelen >= AEON_NAME_LEN)
		return -EINVAL;

	pidir = aeon_get_inode(sb, sih);

	if (pidir->i_new) {
		err = aeon_init_dentry_map(sb, pidir, sih);
		if (err)
			goto out;

		err = aeon_init_dentry(sb, pidir, sih->de_info, ino);
		if (err)
			goto out;
	}

	*d_blocknr = aeon_get_dentry_block(sb, sih->de_info, &new_direntry);
	if (*d_blocknr <= 0) {
		mutex_unlock(&sih->de_info->dentry_mutex);
		goto out;
	}

	aeon_fill_dentry_data(new_direntry, ino, i_blocknr, name, namelen);
	dentry->d_fsdata = (void *)new_direntry;

	err = aeon_insert_dir_tree(sb, sih, name, namelen, new_direntry);
	if (err)
		goto out2;

	dir->i_mtime = dir->i_ctime = current_time(dir);

	pidir->i_links_count++;
	aeon_update_inode_csum(pidir);

	return 0;
out2:
	aeon_release_dentry_block(new_direntry);
out:
	aeon_err(sb, "%s failed\n", __func__);
	return err;
}

int aeon_remove_dentry(struct dentry *dentry, int dec_link,
		       struct aeon_inode *update, struct aeon_dentry *de)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct qstr *entry = &dentry->d_name;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_dentry_info *de_info = sih->de_info;
	struct aeon_inode *pidir = aeon_get_inode(sb, sih);
	struct aeon_dentry_invalid *adi;
	struct aeon_dentry_map *de_map = aeon_get_dentry_map(sb, sih);
	int ret;

	if (!dentry->d_name.len)
		return -EINVAL;

	adi = kmalloc(sizeof(struct aeon_dentry_invalid), GFP_KERNEL);
	if (!adi)
		return -ENOMEM;

	ret = aeon_remove_dir_tree(sb, sih, entry->name, entry->len);
	if (ret)
		goto out;

	adi->internal = le32_to_cpu(de->internal_offset);
	adi->global = le32_to_cpu(de->global_offset);
	list_add(&adi->invalid_list, &de_info->di->invalid_list);

	de_map->num_dentries--;
	de->valid = 0;
	de->i_blocknr = 0;
	memset(de->name, '\0', de->name_len + 1);
	aeon_update_dentry_csum(de);

	dir->i_mtime = dir->i_ctime = current_time(dir);

	pidir->i_links_count--;
	aeon_update_inode_csum(pidir);


	return 0;
out:
	return ret;
}

struct aeon_dentry *aeon_find_dentry(struct super_block *sb,
				     struct aeon_inode *pi,
				     struct inode *inode,
				     const char *name, unsigned long namelen)
{
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_range_node *ret_node = NULL;
	struct aeon_dentry *direntry = NULL;
	unsigned long hash;
	int found;

	hash = BKDRHash(name, namelen);
	found = aeon_find_range_node(&sih->rb_tree, hash, NODE_DIR, &ret_node);
	if (found && (hash == ret_node->hash))
		direntry = ret_node->direntry;

	return direntry;
}

void aeon_set_link(struct inode *dir, struct aeon_dentry *de,
		   struct inode *inode, int update_times)
{
	struct aeon_sb_info *sbi = AEON_SB(dir->i_sb);
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	struct aeon_inode *pi = aeon_get_inode(dir->i_sb, sih);
	unsigned long internal_ino;
	unsigned long new_i_blocknr;
	u32 ino;
	int cpu_id;

	pi = aeon_get_inode(dir->i_sb, sih);

	de->ino = pi->aeon_ino;
	ino = le32_to_cpu(pi->aeon_ino);

	cpu_id = ino % sbi->cpus;
	internal_ino = ino % sbi->cpus;
	if (cpu_id >= sbi->cpus)
		cpu_id -= sbi->cpus;

	new_i_blocknr = ((sih->pi_addr - (u64)sbi->virt_addr) >> AEON_SHIFT) -
						(internal_ino >> AEON_I_SHIFT);
	de->i_blocknr = cpu_to_le64(new_i_blocknr);
}

int aeon_empty_dir(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_dentry_map *de_map;

	de_map = aeon_get_dentry_map(sb, sih);
	if (de_map)
		return 0;

	return 1;
}

void aeon_free_invalid_dentry_list(struct super_block *sb,
				   struct aeon_inode_info_header *sih)
{
	struct aeon_dentry_info *de_info = sih->de_info;
	struct aeon_dentry_invalid *adi;
	struct aeon_dentry_invalid *dend = NULL;

	list_for_each_entry_safe(adi, dend, &de_info->di->invalid_list, invalid_list) {
		//aeon_dbg("%s: Free invalid list (%u - %lu)\n", __func__, adi->internal, adi->global);
		list_del(&adi->invalid_list);
		kfree(adi);
		adi = NULL;
	}
}

static int aeon_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_range_node *curr;
	struct aeon_inode *child_pi;
	struct aeon_dentry *entry;
	struct rb_node *temp = NULL;
	unsigned long pos = ctx->pos;
	int found = 0;
	u32 ino;
	int err;
	u64 pi_addr = 0;

	if (pos == 0)
		temp = rb_first(&sih->rb_tree);
	else if (pos == READDIR_END) {
		dir_emit_dots(file, ctx);
		return 0;
	} else {
		found = aeon_find_range_node(&sih->rb_tree, pos, NODE_DIR, &curr);
		if (found && pos == curr->hash)
			temp = &curr->node;
	}

	while (temp) {
		curr = container_of(temp, struct aeon_range_node, node);
		entry = curr->direntry;

		pos = BKDRHash(entry->name, entry->name_len);
		ctx->pos = pos;
		ino = le32_to_cpu(entry->ino);
		if (ino == 0)
			continue;

		err = aeon_get_inode_address(sb, ino, &pi_addr, entry);
		if (err) {
		      aeon_dbg("%s: get child inode %u address failed %d\n",
		                      __func__, ino, err);
		      aeon_dbg("can't get %s\n", entry->name);
		      ctx->pos = READDIR_END;
		      return err;
		}
		child_pi = (struct aeon_inode *)pi_addr;
		if (!dir_emit(ctx, entry->name, entry->name_len,
			      ino, le16_to_cpu(child_pi->i_mode))) {
			aeon_dbg("%s: pos %lu\n", __func__, pos);
			return 0;
		}

		temp = rb_next(temp);
	}

	ctx->pos = READDIR_END;
	return 0;
}

const struct file_operations aeon_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= aeon_readdir,
	.fsync		= generic_file_fsync,
	.unlocked_ioctl = aeon_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= aeon_compat_ioctl,
#endif
};
