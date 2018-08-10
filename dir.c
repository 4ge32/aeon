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
	struct aeon_dentry_map *de_map = (struct aeon_dentry_map *)(sbi->virt_addr + (blocknr << AEON_SHIFT));
	struct aeon_dentry_map *new_de_map;
	unsigned long la_num_entries = le64_to_cpu(de_map->num_latest_dentry);
	unsigned long num_internal = le64_to_cpu(de_map->num_internal_dentries);
	unsigned long new_de_map_blocknr = 0;
	u64 pi_addr = 0;


	if (la_num_entries == MAX_ENTRY - 1 && num_internal == AEON_INTERNAL_ENTRY) {
		/* create new map */
		aeon_dbg("Hello\n");
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
		aeon_dbg("World\n");
		blocknr = de_map->next_map;
		de_map = (struct aeon_dentry_map *)(sbi->virt_addr + (blocknr << AEON_SHIFT));
		/* dead code so far ? */
		if (de_map->num_dentries == MAX_DENTRY)
			return ERR_PTR(-EMLINK);
	}

	return de_map;

}

static struct aeon_dentry *aeon_init_dentry(struct super_block *sb, struct aeon_dentry_map *de_map,
					    u64 ino, struct aeon_inode *pidir)
{
	struct aeon_dentry *direntry;
	unsigned long d_blocknr;
	u64 pi_addr = 0;

	d_blocknr = aeon_get_new_dentry_block(sb, &pi_addr, ANY_CPU);
	if (d_blocknr == 0)
		return ERR_PTR(-ENOSPC);

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
	de_map->block_dentry[0] = d_blocknr;

	return direntry;
}

static struct aeon_dentry *aeon_allocate_new_dentry_block(struct super_block *sb, u64 ino,
				          		  const char *name, int namelen,
				          		  unsigned long *d_blocknr)
{
	struct aeon_dentry *direntry;
	u64 pi_addr = 0;

	*d_blocknr = aeon_get_new_dentry_block(sb, &pi_addr, ANY_CPU);
	if (*d_blocknr == 0)
		return ERR_PTR(-ENOSPC);

	direntry = (struct aeon_dentry *)pi_addr;
	strncpy(direntry->name, name, namelen);
	direntry->name_len = namelen;
	direntry->ino = ino;

	return direntry;
}

static void aeon_register_dentry_to_map(struct aeon_dentry_map *de_map,
					unsigned long d_blocknr, int new)
{
	if (new)
		de_map->num_latest_dentry = 0;
	else
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


	aeon_dbg("%s: %u - %u\n", __func__, internal_entry, latest_entry);

	list_del(&adi->invalid_list);
	kfree(adi);

	return (struct aeon_dentry *)((u64)sbi->virt_addr + head_addr + internal_offset);
}

int aeon_add_dentry(struct dentry *dentry, u64 ino, int inc_link)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct dentry *parent = dentry->d_parent;
	struct super_block *sb = dir->i_sb;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pidir;
	struct aeon_dentry *direntry = NULL;
	struct aeon_dentry_map *de_map;
	struct aeon_dentry_info *de_info;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	unsigned long d_blocknr = 0;
	unsigned long internal_de;
	unsigned long latest_entry;
	u64 pi_addr = 0;
	int err;

	aeon_dbg("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	aeon_dbg("%s: %s %d\n", __func__, name, namelen);


	/* TODO:
	 * Refine entire code that includes helper funtions.
	 */

	if (namelen == 0)
		return -EINVAL;

	pidir = aeon_get_inode(sb, sih);

	/*
	 * Whether parent directory is new or not.
	 */
	if (pidir->i_new) {
		struct aeon_dentry_invalid *adi;
		de_info = kzalloc(sizeof(struct aeon_dentry_info), GFP_KERNEL);
		adi = kzalloc(sizeof(struct aeon_dentry_invalid), GFP_KERNEL);
		de_info->di = adi;
		// launch new dentry map
		d_blocknr = aeon_get_new_dentry_map_block(sb, &pi_addr, ANY_CPU);
		de_map = (struct aeon_dentry_map *)pi_addr;
		de_map->num_dentries = 0;
		de_map->num_latest_dentry = 0;
		de_map->num_internal_dentries = cpu_to_le64(AEON_INTERNAL_ENTRY);
		pidir->dentry_map_block = cpu_to_le64(d_blocknr);

		direntry = aeon_init_dentry(sb, de_map, ino, pidir);

		INIT_LIST_HEAD(&de_info->di->invalid_list);
		de_info->de_map = de_map;
		parent->d_fsdata = (void *)de_info;
		sih->de_info = de_info;

		pidir->i_new = 0;
	} else {
		aeon_dbg("iiHERE!!!???\n");
		de_map = aeon_get_dentry_map(sb, pidir);
		if (IS_ERR(de_map))
			return -EMLINK;
	}

	aeon_dbg("HERE!!!???\n");
	de_info = sih->de_info;

	if (!isInvalidSpace(de_info)) {
		aeon_dbg("HERE1\n");
		internal_de = le64_to_cpu(de_map->num_internal_dentries);
		/*
		 * When running out of allocated page that is for dentry.
		 */
		if (internal_de == AEON_INTERNAL_ENTRY) {
			// allocate new dentry page
			direntry = aeon_allocate_new_dentry_block(sb, ino, name, namelen, &d_blocknr);
			if (IS_ERR(direntry))
				return -ENOSPC;
			// register new dentry page to map
			aeon_register_dentry_to_map(de_map, d_blocknr, 0);

			direntry->internal_offset = 0;
			direntry->global_offset = (de_map->num_latest_dentry - 1);
			direntry->valid = 1;

			goto end;
		}

		// use remained page for allocating dentry.
		direntry = aeon_get_internal_dentry(sb, de_map);
		strncpy(direntry->name, name, namelen);
		*(direntry->name + namelen) = '\0';
		direntry->name_len = namelen;
		direntry->ino = ino;
		direntry->internal_offset = de_map->num_internal_dentries;
		direntry->global_offset = de_map->num_latest_dentry;
		direntry->valid = 1;

		aeon_dbg("%s: %lld - %u\n", __func__, le64_to_cpu(direntry->internal_offset),
				le32_to_cpu(direntry->global_offset));

		de_map->num_internal_dentries++;
	} else {
		aeon_dbg("HERE2\n");
		direntry = aeon_reuse_space_for_dentry(sb, de_map, de_info);
		strncpy(direntry->name, name, namelen);
		*(direntry->name + namelen) = '\0';
		direntry->name_len = namelen;
		direntry->ino = ino;
		direntry->valid = 1;

		aeon_dbg("%s: %lld - %u\n", __func__, le64_to_cpu(direntry->internal_offset),
				le32_to_cpu(direntry->global_offset));

	}

end:
	de_map->num_dentries++;


	err = aeon_insert_dir_tree(sb, sih, name, namelen, direntry);
	if (err)
		return -ENOMEM;

	dir->i_mtime = dir->i_ctime = current_time(dir);

	latest_entry = le64_to_cpu(de_map->num_latest_dentry);
	aeon_dbg("%s: %llu\n", __func__, (le64_to_cpu(de_map->block_dentry[latest_entry])));
	aeon_dbg("%s: %llu\n", __func__, le64_to_cpu(de_map->num_internal_dentries));
	aeon_dbg("%s: %llu\n", __func__, le64_to_cpu(de_map->num_dentries));

	return 0;
}

int aeon_remove_dentry(struct dentry *dentry, int dec_link,
		       struct aeon_inode *update, struct aeon_dentry *de)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct dentry *parent = dentry->d_parent;
	struct aeon_dentry_info *de_info = (struct aeon_dentry_info *)parent->d_fsdata;
	struct super_block *sb = dir->i_sb;
	struct qstr *entry = &dentry->d_name;
	struct aeon_inode_info *si = AEON_I(dir);
	struct aeon_inode_info_header *sih = &si->header;
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
	list_add(&adi->invalid_list, &de_info->di->invalid_list);
	aeon_dbg("%s: %u - %lu\n", __func__, adi->internal, adi->global);

	de_map->num_dentries--;
	aeon_dbg("%s: num_dentries - %llu\n", __func__, le64_to_cpu(de_map->num_dentries));
	de->valid = 0;
	memset(de->name, '\0', de->name_len);

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


/*
 * TODO:
 * want to integrate funtion of except first
 */
static struct aeon_dentry_map *aeon_get_first_dentry_map(struct super_block *sb, struct aeon_inode *pi, bool first)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long blocknr = le64_to_cpu(pi->dentry_map_block);
	struct aeon_dentry_map *de_map;

	if (blocknr == 0)
		return NULL;

	de_map = (struct aeon_dentry_map *)(sbi->virt_addr + (blocknr << AEON_SHIFT));
	if (le64_to_cpu(de_map->num_dentries) == 2)
		return NULL;

	return de_map;

}

int aeon_empty_dir(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_dentry_map *de_map;

	de_map = aeon_get_first_dentry_map(sb, pi, 0);
	if (de_map)
		return 0;

	return 1;
}

static struct aeon_dentry *aeon_pull_dentry(struct super_block *sb, struct aeon_dentry_map *de_map,
				     unsigned int internal, unsigned long global)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long head_addr = le64_to_cpu(de_map->block_dentry[global]) << AEON_SHIFT;

	return (struct aeon_dentry *)((u64)sbi->virt_addr + head_addr + (internal << AEON_D_SHIFT));
}

void aeon_free_invalid_dentry_list(struct super_block *sb, struct aeon_inode_info_header *sih)
{
	struct aeon_dentry_info *de_info = sih->de_info;
	struct aeon_dentry_invalid *adi;
	struct aeon_dentry_map *de_map = de_info->de_map;
	struct aeon_dentry *direntry;

	list_for_each_entry(adi, &de_info->di->invalid_list, invalid_list) {
		/* TODO: Still in progress */
		aeon_dbg("%s: Free invalid list (%u - %lu)\n", __func__, adi->internal, adi->global);
		direntry = aeon_pull_dentry(sb, de_map, adi->internal, adi->global);
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
			ino = le64_to_cpu(entry->ino);
			if (ino == 0)
				continue;


			child_pi = aeon_get_inode(sb, sih);
			aeon_dbg("ctx: ino %llu, name %s, name_len %u\n",
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
