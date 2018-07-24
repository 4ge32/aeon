#include <linux/fs.h>

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
	struct aeon_dentry_map *de_map = (struct aeon_dentry_map *)(sbi->virt_addr + blocknr * AEON_DEF_BLOCK_SIZE_4K);
	struct aeon_dentry_map *new_de_map;
	unsigned long num_entries = le64_to_cpu(de_map->num_dentries);
	unsigned long new_de_map_blocknr = 0;
	u64 pi_addr = 0;

	if (num_entries == MAX_ENTRY) {
		/* create new map */
		new_de_map_blocknr = aeon_get_new_dentry_map_block(sb, &pi_addr, ANY_CPU);
		new_de_map = (struct aeon_dentry_map *)pi_addr;
		new_de_map->num_dentries = 0;
		de_map->next_map = new_de_map_blocknr;
		de_map->num_dentries++;

		de_map = new_de_map;
	} else if (num_entries == MAX_ENTRY + 1) {
		/* return next map */
		blocknr = de_map->next_map;
		de_map = (struct aeon_dentry_map *)(sbi->virt_addr + blocknr * AEON_DEF_BLOCK_SIZE_4K);
		if (de_map->num_dentries == MAX_ENTRY)
			return ERR_PTR(-ENOSPC);
	}

	return de_map;

}

int aeon_add_dentry(struct dentry *dentry, u64 ino, int inc_link)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pidir;
	struct aeon_dentry *direntry;
	struct aeon_dentry_map *de_map;
	const char *name = dentry->d_name.name;
	unsigned long num_de;
	int namelen = dentry->d_name.len;
	unsigned long d_blocknr = 0;
	u64 pi_addr = 0;
	int err;

	aeon_dbg("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	aeon_dbg("%s: %s %d\n", __func__, name, namelen);

	if (namelen == 0)
		return -EINVAL;

	pidir = aeon_get_inode(sb, sih);

	if (pidir->i_new) {
		d_blocknr = aeon_get_new_dentry_map_block(sb, &pi_addr, ANY_CPU);
		de_map = (struct aeon_dentry_map *)pi_addr;
		de_map->num_dentries = 0;
		pidir->i_new = 0;
		pidir->dentry_map_block = cpu_to_le64(d_blocknr);
	} else {
		de_map = aeon_get_dentry_map(sb, pidir);
		if (IS_ERR(de_map))
			return -ENOSPC;
	}

	num_de = le64_to_cpu(de_map->num_dentries);

	d_blocknr = aeon_get_new_dentry_block(sb, &pi_addr, ANY_CPU);
	direntry = (struct aeon_dentry *)pi_addr;
	strncpy(direntry->name, name, namelen);
	direntry->name_len = namelen;
	direntry->ino = ino;

	de_map->block_dentry[num_de] = d_blocknr;
	de_map->num_dentries = cpu_to_le64(++num_de);

	err = aeon_insert_dir_tree(sb, sih, name, namelen, direntry);
	if (err)
		return -ENOMEM;

	dir->i_mtime = dir->i_ctime = current_time(dir);

	return 0;
}

int aeon_remove_dentry(struct dentry *dentry, int dec_link, struct aeon_inode *update)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct qstr *entry = &dentry->d_name;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pidir;
	int ret;

	if (!dentry->d_name.len)
		return -EINVAL;

	ret = aeon_remove_dir_tree(sb, sih, entry->name, entry->len);
	if (ret)
		goto out;

	pidir = aeon_get_inode(sb, sih);

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

	pidir = aeon_get_inode(sb, sih);
	aeon_dbg("%s: ino %llu, size %llu, pos %llu\n",
			__func__, (u64)inode->i_ino,
			pidir->i_size, ctx->pos);

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
			ino = __le64_to_cpu(entry->ino);
			if (ino == 0)
				continue;


			child_pi = aeon_get_inode(sb, sih);
			aeon_dbg("ctx: ino %llu, name %s, name_len %u, de_len %u\n",
					(u64)ino, entry->name, entry->name_len,
					entry->de_len);
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
