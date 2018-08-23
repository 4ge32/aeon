#include <linux/fs.h>
#include <linux/slab.h>

#include "aeon.h"


#define IF2DT(sif) (((sif) & S_IFMT) >> 12)
#define FREE_BATCH 16

int aeon_insert_dir_tree(struct super_block *sb, struct aeon_inode_info_header *sih,
			 const char *name, int namelen, struct aeon_dentry *direntry)
{
	unsigned long hash;
	int ret;

	hash = BKDRHash(name, namelen);

	ret = radix_tree_insert(&sih->tree, hash, direntry);
	if (ret) {
		aeon_dbg("%s ERROR %d: %s\n", __func__, ret, name);
	}

	return ret;
}

static int aeon_remove_dir_tree(struct super_block *sb, struct aeon_inode_info_header *sih,
			 const char *name, int namelen)
{
	struct aeon_dentry *entry;
	unsigned long hash;

	hash = BKDRHash(name, namelen);
	entry = radix_tree_delete(&sih->tree, hash);

	return 0;
}

struct aeon_dentry *aeon_dotdot(struct super_block *sb, struct aeon_inode_info_header *sih)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode *pi;
	struct aeon_dentry_map *de_map;
	struct aeon_dentry *de;
	unsigned long de_map_block;
	unsigned long dotdot_block;

	pi = aeon_get_inode(sb, sih);

	de_map_block = le64_to_cpu(pi->dentry_map_block);
	de_map = (struct aeon_dentry_map *)((u64)sbi->virt_addr + (de_map_block << AEON_SHIFT));

	dotdot_block = le64_to_cpu(de_map->block_dentry[0]);
	de = (struct aeon_dentry *)((u64)sbi->virt_addr + (dotdot_block << AEON_SHIFT) +
				    (1 << AEON_D_SHIFT));

	return de;
}

void aeon_delete_dir_tree(struct super_block *sb, struct aeon_inode_info_header *sih)
{
	struct aeon_dentry *direntry;
	unsigned long pos = 0;
	struct aeon_dentry *entries[FREE_BATCH];
	int nr_entries;
	int i;
	void *ret;

	do {
		nr_entries = radix_tree_gang_lookup(&sih->tree, (void **)entries, pos, FREE_BATCH);
		for (i = 0; i < nr_entries; i++) {
			direntry = entries[i];

			pos = BKDRHash(direntry->name, direntry->name_len);
			ret = radix_tree_delete(&sih->tree, pos);
			if (!ret || ret != direntry) {
				aeon_err(sb, "dentry: type %d, inode %llu, name %s, namelen %u, rec len %u\n",
						direntry->entry_type,
						le64_to_cpu(direntry->ino),
						direntry->name, direntry->name_len,
						le16_to_cpu(direntry->de_len));
				if (!ret)
					aeon_dbg("ret is NULL\n");
			}
		}
		pos ++;
	} while (nr_entries == FREE_BATCH);
}

static struct aeon_dentry_map *aeon_get_dentry_map(struct super_block *sb, struct aeon_inode *pi)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long blocknr = le64_to_cpu(pi->dentry_map_block);
	struct aeon_dentry_map *de_map;
	struct aeon_dentry_map *new_de_map;
	unsigned long la_num_entries;
	unsigned long num_internal;
	unsigned long new_de_map_blocknr = 0;
	u64 pi_addr = 0;

	de_map = (struct aeon_dentry_map *)(sbi->virt_addr + (blocknr << AEON_SHIFT));
	la_num_entries = le64_to_cpu(de_map->num_latest_dentry);
	num_internal = le64_to_cpu(de_map->num_internal_dentries);

	if (la_num_entries == MAX_ENTRY - 1 && num_internal == AEON_INTERNAL_ENTRY) {
		/* create new map */
		new_de_map_blocknr = aeon_get_new_dentry_map_block(sb, &pi_addr, ANY_CPU);
		new_de_map = (struct aeon_dentry_map *)pi_addr;
		new_de_map->num_dentries = 0;
		new_de_map->num_latest_dentry = 0;
		new_de_map->num_internal_dentries = cpu_to_le64(AEON_INTERNAL_ENTRY);

		de_map->next_map = new_de_map_blocknr;
		de_map->num_latest_dentry++;
		de_map->num_dentries++;

		new_de_map->num_dentries = (--de_map->num_dentries);
		de_map = new_de_map;
	} else if (la_num_entries == MAX_ENTRY) {
		/* return next map */
		blocknr = de_map->next_map;
		de_map = (struct aeon_dentry_map *)(sbi->virt_addr + (blocknr << AEON_SHIFT));
		/* dead code so far ? */
		if (de_map->num_dentries == MAX_DENTRY)
			return ERR_PTR(-EMLINK);
	}

	return de_map;

}

static void aeon_register_dentry_to_map(struct aeon_dentry_map *de_map,
					unsigned long d_blocknr)
{
	de_map->num_latest_dentry++;
	de_map->block_dentry[le64_to_cpu(de_map->num_latest_dentry)] = d_blocknr;
	de_map->num_internal_dentries = 1;
}

static struct aeon_dentry *aeon_get_internal_dentry(struct super_block *sb,
						    struct aeon_dentry_map *de_map)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned int latest_entry = le64_to_cpu(de_map->num_latest_dentry);
	unsigned int internal_entry = le64_to_cpu(de_map->num_internal_dentries);
	unsigned long head_addr = le64_to_cpu(de_map->block_dentry[latest_entry]) << AEON_SHIFT;
	unsigned int internal_offset = internal_entry << AEON_D_SHIFT;

	return (struct aeon_dentry *)((u64)sbi->virt_addr + head_addr + internal_offset);
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
						       struct aeon_dentry_info *de_info)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_dentry_invalid *adi = list_first_entry(&de_info->di->invalid_list,
							   struct aeon_dentry_invalid,
							   invalid_list);
	unsigned int latest_entry = adi->global;
	unsigned int internal_entry = adi->internal;
	unsigned long head_addr = le64_to_cpu(de_map->block_dentry[latest_entry]) << AEON_SHIFT;
	unsigned int internal_offset = internal_entry << AEON_D_SHIFT;

	mutex_lock(&de_info->dentry_mutex);
	list_del(&adi->invalid_list);
	mutex_unlock(&de_info->dentry_mutex);

	kfree(adi);

	return (struct aeon_dentry *)((u64)sbi->virt_addr + head_addr + internal_offset);
}

static int aeon_init_dentry_map(struct super_block *sb,
				struct aeon_inode *pidir,
				struct aeon_inode_info_header *sih)
{
	struct aeon_dentry_info *de_info;
	struct aeon_dentry_map *de_map;
	struct aeon_dentry_invalid *adi;
	unsigned long blocknr;
	u64 pi_addr = 0;

	de_info = kzalloc(sizeof(struct aeon_dentry_info), GFP_KERNEL);
	if (!de_info)
		return -ENOMEM;

	adi = kzalloc(sizeof(struct aeon_dentry_invalid), GFP_KERNEL);
	if (!adi) {
		kfree(de_info);
		return -ENOMEM;
	}

	blocknr = aeon_get_new_dentry_map_block(sb, &pi_addr, ANY_CPU);
	de_map = (struct aeon_dentry_map *)pi_addr;
	de_map->num_dentries = 0;
	de_map->num_latest_dentry = 0;
	de_map->num_internal_dentries = cpu_to_le64(AEON_INTERNAL_ENTRY);

	de_info->de_map = de_map;
	de_info->di = adi;
	sih->de_info = de_info;

	INIT_LIST_HEAD(&de_info->di->invalid_list);

	pidir->dentry_map_block = cpu_to_le64(blocknr);
	pidir->i_new = 0;

	return 0;
}

static int aeon_init_dentry(struct super_block *sb, struct aeon_inode *pidir,
			    struct aeon_dentry_info *de_info, ino_t ino)
{
	struct aeon_dentry *direntry;
	struct aeon_dentry_map *de_map = de_info->de_map;
	unsigned long blocknr;
	u64 pi_addr = 0;

	blocknr = aeon_get_new_dentry_block(sb, &pi_addr, ANY_CPU);
	if (blocknr == 0)
		return -ENOSPC;

	direntry = (struct aeon_dentry *)pi_addr;
	strncpy(direntry->name, ".\0", 2);
	direntry->name_len = 2;
	direntry->ino = ino;
	direntry->valid = 1;

	direntry = (struct aeon_dentry *)(pi_addr + (1 << AEON_D_SHIFT));
	strncpy(direntry->name, "..\0", 3);
	direntry->name_len = 3;
	direntry->ino = pidir->aeon_ino;
	direntry->valid = 1;

	de_map->num_internal_dentries = cpu_to_le64(2);
	de_map->num_dentries = cpu_to_le64(2);
	de_map->block_dentry[0] = blocknr;

	de_info->de = direntry;

	return 0;
}

static struct aeon_dentry *aeon_allocate_new_dentry_block(struct super_block *sb,
				          		  unsigned long *d_blocknr)
{
	struct aeon_dentry *direntry;
	u64 pi_addr = 0;

	*d_blocknr = aeon_get_new_dentry_block(sb, &pi_addr, ANY_CPU);
	if (*d_blocknr == 0)
		return ERR_PTR(-ENOSPC);

	direntry = (struct aeon_dentry *)pi_addr;

	return direntry;
}

static int aeon_get_dentry_block(struct super_block *sb,
			         struct aeon_dentry_info *de_info,
				 struct aeon_dentry **direntry)
{
	struct aeon_dentry_map *de_map = de_info->de_map;
	unsigned long internal_de;
	unsigned long blocknr = 0;

	if(!isInvalidSpace(de_info)) {
		internal_de = le64_to_cpu(de_map->num_internal_dentries);

		if (internal_de == AEON_INTERNAL_ENTRY) {

			*direntry = aeon_allocate_new_dentry_block(sb, &blocknr);
			if (IS_ERR(*direntry))
				return -ENOSPC;
			aeon_register_dentry_to_map(de_map, blocknr);
			(*direntry)->internal_offset = 0;
			(*direntry)->global_offset = (de_map->num_latest_dentry - 1);

		} else {
			*direntry = aeon_get_internal_dentry(sb, de_map);
			(*direntry)->internal_offset = de_map->num_internal_dentries;
			(*direntry)->global_offset = de_map->num_latest_dentry;

			de_map->num_internal_dentries++;
		}

	} else {
		*direntry = aeon_reuse_space_for_dentry(sb, de_map, de_info);

		(*direntry)->internal_offset = de_map->num_internal_dentries;
		(*direntry)->global_offset = de_map->num_latest_dentry;
	}

	(*direntry)->valid = 1;
	de_map->num_dentries++;

	return 0;
}

static void aeon_fill_dentry_info(struct aeon_dentry *de, ino_t ino, const char *name, int namelen)
{
	de->name_len = le32_to_cpu(namelen);
	de->ino = le32_to_cpu(ino);
	strscpy(de->name, name, namelen + 1);
}

static void aeon_release_dentry_block(struct aeon_dentry *de)
{
	de->valid = 0;
}

int aeon_add_dentry(struct dentry *dentry, ino_t ino, int inc_link)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pidir;
	struct aeon_dentry_info *de_info;
	struct aeon_dentry *new_direntry = NULL;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	int err;
	unsigned long latest_entry;

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

	de_info = sih->de_info;

	err = aeon_get_dentry_block(sb, de_info, &new_direntry);
	if (err)
		goto out;

	aeon_fill_dentry_info(new_direntry, ino, name, namelen);

	err = aeon_insert_dir_tree(sb, sih, name, namelen, new_direntry);
	if (err)
		goto out2;

	dir->i_mtime = dir->i_ctime = current_time(dir);

	latest_entry = le64_to_cpu(de_info->de_map->num_latest_dentry);
	aeon_dbgv("%s: %lu\n", __func__, (latest_entry));
	aeon_dbgv("%s: %llu\n", __func__, (le64_to_cpu(de_info->de_map->block_dentry[latest_entry])));
	aeon_dbgv("%s: %llu\n", __func__, le64_to_cpu(de_info->de_map->num_internal_dentries));
	aeon_dbgv("%s: %llu\n", __func__, le64_to_cpu(de_info->de_map->num_dentries));

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
	struct aeon_dentry_invalid *adi = kmalloc(sizeof(struct aeon_dentry_invalid), GFP_KERNEL);
	struct aeon_dentry_map *de_map = aeon_get_dentry_map(sb, pidir);
	int ret;

	if (!dentry->d_name.len)
		return -EINVAL;

	ret = aeon_remove_dir_tree(sb, sih, entry->name, entry->len);
	if (ret)
		goto out;

	adi->internal = le64_to_cpu(de->internal_offset);
	adi->global = le32_to_cpu(de->global_offset);

	mutex_lock(&de_info->dentry_mutex);
	list_add(&adi->invalid_list, &de_info->di->invalid_list);
	mutex_unlock(&de_info->dentry_mutex);

	de_map->num_dentries--;
	de->valid = 0;
	memset(de->name, '\0', de->name_len + 1);

	dir->i_mtime = dir->i_ctime = current_time(dir);

	return 0;
out:
	return ret;
}

struct aeon_dentry *aeon_find_dentry(struct super_block *sb,
	struct aeon_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len)
{
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_dentry *direntry = NULL;
	unsigned long hash;

	hash = BKDRHash(name, name_len);
	direntry = radix_tree_lookup(&sih->tree, hash);

	return direntry;
}

void aeon_set_link(struct inode *dir, struct aeon_dentry *de,
		   struct inode *inode, int update_times)
{
	de->ino = cpu_to_le32(inode->i_ino);
}

int aeon_empty_dir(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_dentry_map *de_map;

	de_map = aeon_get_first_dentry_map(sb, pi);
	if (de_map)
		return 0;

	return 1;
}

void aeon_free_invalid_dentry_list(struct super_block *sb, struct aeon_inode_info_header *sih)
{
	struct aeon_dentry_info *de_info = sih->de_info;
	struct aeon_dentry_invalid *adi;
	struct aeon_dentry_invalid *dend = NULL;

	list_for_each_entry_safe(adi, dend, &de_info->di->invalid_list, invalid_list) {
		aeon_dbg("%s: Free invalid list (%u - %lu)\n", __func__, adi->internal, adi->global);
		list_del(&adi->invalid_list);
		kfree(adi);
	}
}

static int aeon_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct aeon_inode *pidir;
	struct aeon_inode *child_pi;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_dentry *entries[FREE_BATCH];
	struct aeon_dentry *entry;
	unsigned long pos = 0;
	int nr_entries;
	int i;
	ino_t ino;


	if (!dir_emit_dots(file, ctx))
		return 0;

	pidir = aeon_get_inode(sb, sih);

	if (!sih) {
		aeon_dbg("%s: inode %lu sih does not exist!\n",
				__func__, inode->i_ino);
		ctx->pos = READDIR_END;
		return 0;
	}

	pos = ctx->pos;
	if (pos == READDIR_END)
		return 0;

	do {
		nr_entries = radix_tree_gang_lookup(&sih->tree, (void *)entries, pos, FREE_BATCH);
		for (i = 0; i < nr_entries; i++) {
			entry = entries[i];

			pos = BKDRHash(entry->name, entry->name_len);
			ino = le64_to_cpu(entry->ino);
			if (ino == 0)
				continue;


			child_pi = aeon_get_inode(sb, sih);
			aeon_dbgv("ctx: ino %llu, name %s, name_len %u\n",
					(u64)ino, entry->name, entry->name_len);
			if (!dir_emit(ctx, entry->name, entry->name_len,
						ino, IF2DT(child_pi->i_mode))) {
				aeon_dbg("Here: pos %llu\n", ctx->pos);
				return 0;
			}
			ctx->pos = pos + 1;
		}
		pos++;
	} while (nr_entries == FREE_BATCH);

	pos = READDIR_END;

	return 0;

}

const struct file_operations aeon_dir_operations = {
	.iterate = aeon_readdir,
};
