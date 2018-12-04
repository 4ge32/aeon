#include <linux/fs.h>
#include <linux/slab.h>

#include "aeon.h"
#include "aeon_super.h"
#include "aeon_balloc.h"


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
	u64 addr;

	if (pi->aeon_ino == cpu_to_le32(AEON_ROOT_INO))
		return 0;

	addr = le64_to_cpu(pi->i_dentry_addr);
	if (addr <= 0 || addr > sbi->last_addr) {
		aeon_err(sb, "out of bounds i_blocknr 0x%llx last 0x%llx\n",
			 addr, sbi->last_addr);
		return -ENOENT;
	}

	*de_addr = (u64)sbi->virt_addr + addr;
	de = (struct aeon_dentry *)(*de_addr);
	if (pi->aeon_ino != de->ino) {
		u32 pi_ino = le32_to_cpu(pi->aeon_ino);
		u32 de_ino = le32_to_cpu(de->ino);

		aeon_err(sb, "%s: pi_ino %u de_ino %u\n"
			 , __func__, pi_ino, de_ino);
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

int aeon_delete_dir_tree(struct super_block *sb,
			 struct aeon_inode_info_header *sih)
{
	struct aeon_dentry_map *de_map;
	int length = AEON_PAGES_FOR_DENTRY;
	int err = 0;
	int i;

	de_map = aeon_get_dentry_map(sb, sih);
	if (!de_map)
		goto out;

	for (i = 0; i < de_map->num_latest_dentry; i++) {
		unsigned long blocknr;

		blocknr = de_map->block_dentry[i];
		err = aeon_insert_blocks_into_free_list(sb, blocknr, length, 0);
		if (err) {
			aeon_err(sb, "%s: free dentry resource\n", __func__);
			goto out;
		}

	}

out:
	aeon_destroy_range_node_tree(sb, &sih->rb_tree);
	aeon_free_invalid_dentry_list(sb, sih);
	kfree(sih->de_info);
	sih->de_info = NULL;

	return err;
}

static int isInvalidSpace(struct aeon_dentry_info *de_info)
{
	struct aeon_dentry_invalid *di = de_info->di;

	if (list_empty(&di->invalid_list))
		return 0;
	return 1;
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

static struct aeon_dentry *aeon_reuse_space_for_dentry(struct super_block *sb,
						       struct aeon_dentry_map *de_map,
						       struct aeon_dentry_info *de_info,
						       u64 *blocknr)
{
	struct aeon_dentry *de;
	struct aeon_dentry_invalid *adi = list_first_entry(&de_info->di->invalid_list,
							   struct aeon_dentry_invalid,
							   invalid_list);

	de = (struct aeon_dentry *)adi->d_addr;
	*blocknr = (u64)de >> AEON_SHIFT;

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

static int aeon_init_dentry(struct super_block *sb, struct aeon_inode *pi,
			    struct aeon_inode_info_header *sih, u32 ino)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_dentry *direntry;
	struct aeon_dentry_info *de_info = sih->de_info;
	struct aeon_dentry_map *de_map = &de_info->de_map;
	unsigned long blocknr;
	u64 de_addr = 0;
	u64 pi_addr = 0;
	u64 de_addr_base = 0;

	blocknr = aeon_get_new_dentry_block(sb, &de_addr);
	if (blocknr == 0)
		return -ENOSPC;

	pi_addr = (u64)pi - (u64)sbi->virt_addr;
	de_addr_base = de_addr - (u64)sbi->virt_addr;
	direntry = (struct aeon_dentry *)de_addr;
	strncpy(direntry->name, ".\0", 2);
	direntry->name_len = 2;
	direntry->ino = cpu_to_le32(pi->aeon_ino);
	direntry->d_pinode_addr = cpu_to_le64(pi->i_pinode_addr);
	direntry->d_inode_addr = cpu_to_le64(pi_addr);
	direntry->d_dentry_addr = cpu_to_le64(de_addr_base);
	direntry->valid = 1;
	direntry->persisted = 1;
	aeon_update_dentry_csum(direntry);

	de_addr_base += sizeof(struct aeon_dentry);
	direntry = (struct aeon_dentry *)(de_addr + (1 << AEON_D_SHIFT));
	strncpy(direntry->name, "..\0", 3);
	direntry->name_len = 3;
	direntry->ino = cpu_to_le32(pi->parent_ino);
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
	u64 de_addr = 0;

	*d_blocknr = aeon_get_new_dentry_block(sb, &de_addr);
	if (*d_blocknr == 0)
		return ERR_PTR(-ENOSPC);

	direntry = (struct aeon_dentry *)de_addr;

	return direntry;
}

static int aeon_get_dentry_space(struct super_block *sb,
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
		} else {
			*direntry = aeon_get_internal_dentry(sb, de_map, &blocknr);
			de_map->num_internal_dentries++;
		}

	} else
		*direntry = aeon_reuse_space_for_dentry(sb, de_map, de_info, &blocknr);

	(*direntry)->valid = 1;
	de_map->num_dentries++;

	return 0;
}

static
void aeon_fill_dentry_data(struct super_block *sb, struct aeon_dentry *de,
				  u32 ino, u64 pi_addr, u64 pidir_addr,
				  const char *name, int namelen)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	u64 i_addr_offset = pi_addr - (u64)sbi->virt_addr;
	u64 d_addr_offset = (u64)de - (u64)sbi->virt_addr;
	u64 i_paddr_offset = pidir_addr - (u64)sbi->virt_addr;

	de->name_len = le32_to_cpu(namelen);
	de->ino = cpu_to_le32(ino);
	de->d_pinode_addr = cpu_to_le64(i_paddr_offset);
	de->d_inode_addr = cpu_to_le64(i_addr_offset);
	de->d_dentry_addr = cpu_to_le64(d_addr_offset);
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

u64 aeon_add_dentry(struct dentry *dentry, u32 ino,
		    u64 pi_addr, int inc_link)
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

		err = aeon_init_dentry(sb, pidir, sih, ino);
		if (err)
			goto out;
	}

	err = aeon_get_dentry_space(sb, sih->de_info, &new_direntry);
	if (err)
		goto out;

	aeon_fill_dentry_data(sb, new_direntry, ino, pi_addr,
			      (u64)pidir, name, namelen);
	dentry->d_fsdata = (void *)new_direntry;

	err = aeon_insert_dir_tree(sb, sih, name, namelen, new_direntry);
	if (err)
		goto out2;

	dir->i_mtime = dir->i_ctime = current_time(dir);
	pidir->i_links_count++;
	aeon_update_inode_csum(pidir);

	return (u64)new_direntry;
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
	int err;

	if (!dentry->d_name.len)
		return -EINVAL;

	adi = kmalloc(sizeof(struct aeon_dentry_invalid), GFP_KERNEL);
	if (!adi)
		return -ENOMEM;

	err = aeon_remove_dir_tree(sb, sih, entry->name, entry->len);
	if (err)
		goto out;

	mutex_lock(&de_info->dentry_mutex);

	adi->d_addr = (u64)de;
	list_add(&adi->invalid_list, &de_info->di->invalid_list);
	de_map->num_dentries--;
	de->valid = 0;
	memset(de->name, '\0', de->name_len + 1);
	aeon_update_dentry_csum(de);

	mutex_unlock(&de_info->dentry_mutex);

	dir->i_mtime = dir->i_ctime = current_time(dir);

	pidir->i_links_count--;
	aeon_update_inode_csum(pidir);


	return 0;
out:
	return err;
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

	pi = aeon_get_inode(dir->i_sb, sih);

	de->ino = pi->aeon_ino;
	de->d_inode_addr = cpu_to_le64(sih->pi_addr - (u64)sbi->virt_addr);
}

int aeon_empty_dir(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_dentry_map *de_map;

	de_map = aeon_get_dentry_map(sb, sih);
	if (!de_map)
		return 0;
	if (de_map->num_dentries == 2)
		return 0;

	return 1;
}

int aeon_free_cached_dentry_blocks(struct super_block *sb,
				   struct aeon_inode_info_header *sih)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_dentry_map *de_map;
	struct aeon_dentry *de;
	unsigned long blocknr;
	int global;
	int internal;
	int err;
	bool free;

	de_map = aeon_get_dentry_map(sb, sih);
	if (!de_map)
		return 0;

	/* It can be improved */
	for (global = 1; global <= de_map->num_latest_dentry; global++) {
		free = true;
		blocknr = de_map->block_dentry[global];
		aeon_dbg("blocknr %lu\n", blocknr);
		for (internal = 0; internal < AEON_INTERNAL_ENTRY; internal++) {
			de = (struct aeon_dentry *)(sbi->virt_addr +
						    (blocknr << AEON_SHIFT) +
						    (internal << AEON_D_SHIFT));
			if (de->valid) {
				free = false;
				break;
			}
		}
		if (free) {
			err = aeon_insert_blocks_into_free_list(sb, blocknr,
						AEON_PAGES_FOR_DENTRY, 0);
			if (err) {
				aeon_err(sb, "%s\n", __func__);
				return -EINVAL;
			}
		}
	}

	return 0;
}

void aeon_free_invalid_dentry_list(struct super_block *sb,
				   struct aeon_inode_info_header *sih)
{
	struct aeon_dentry_info *de_info = sih->de_info;
	struct aeon_dentry_invalid *adi;
	struct aeon_dentry_invalid *dend = NULL;

	if (!de_info)
		return;

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
	else if (pos == READDIR_END)
		return 0;
	else {
		found = aeon_find_range_node(&sih->rb_tree, pos, NODE_DIR, &curr);
		if (found && pos == curr->hash)
			temp = &curr->node;
	}

	if (!dir_emit_dots(file, ctx))
		return -EINVAL;

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
