#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/random.h>

#include "aeon.h"

#define FULL_PERSIST		31
#define P_INODE_PERIST		17
#define P_DENTRY_PERSIST	9
#define C_INODE_PERSIST		5
#define C_DENTRY_PERSIST	3
#define	PARENT_PERSIST		(P_INODE_PERIST | P_DENTRY_PERSIST)
#define	P_AND_C_INODE_PERSIST	(PARENT_PERSIST | C_INODE_PERSIST)
#define	P_AND_C_DENTRY_PERSIST	(PARENT_PERSIST | C_DENTRY_PERSIST)
#define CASE1			(PARENT_PERSIST)
#define NOT_FOUND		1

static void add_block_entry(struct aeon_dentry_map *de_map,
			    u64 blocknr, bool *first)
{
	int i;

	if (first && *first) {
		de_map->block_dentry[0] = blocknr;
		*first = false;
		return;
	}

	for (i = 0; i <= de_map->num_latest_dentry; i++) {
		if (de_map->block_dentry[i] == blocknr)
			return;
	}

	de_map->block_dentry[++de_map->num_latest_dentry]
		= le64_to_cpu(blocknr);
}

static int aeon_check_parent_dir_state(int state)
{
	if (state && PARENT_PERSIST)
		return 0;
	return state;
}

static int aeon_check_child(int p_state, int c_state)
{
	int state = p_state | c_state;

	if (state == FULL_PERSIST)
		return 0;
	else
		return state;
}

static void aeon_rebuild_dentry(struct aeon_dentry *dest,
				struct aeon_dentry *src, struct aeon_inode *pi)
{
	int name_len;

	name_len = src->name_len;
	if (0 < name_len && name_len < AEON_NAME_LEN) {
		if (src->name[0] != '\0' && src->name[name_len + 1] == '\0') {
			strscpy(dest->name, src->name, name_len + 1);
			dest->name_len = strlen(dest->name);
			goto next;
		}
	}
	snprintf(dest->name, AEON_NAME_LEN, "R-%u",
		 le32_to_cpu(pi->aeon_ino));
	dest->name_len = strlen(dest->name);

next:
	dest->ino = pi->aeon_ino;
	dest->d_pinode_addr = pi->i_pinode_addr;
	dest->d_dentry_addr = pi->i_dentry_addr;
	dest->d_inode_addr = pi->i_inode_addr;
	dest->valid = 1;
	dest->persisted = 1;
	aeon_update_dentry_csum(dest);
}

static void aeon_rebuild_inode(struct aeon_inode *pi, struct aeon_dentry *de,
			       struct aeon_inode *parent)
{
	/*
	 * First two are possibity when system failure occures in creating
	 * process. There is a possibility that uid & gid would belong root user & group
	 */
	if (pi->i_flags == 0) {
		pi->i_flags |= le16_to_cpu(S_DAX);
		pi->i_flags |= le16_to_cpu(S_SYNC);
	}
	if (pi->i_mode == 0)
		pi->i_mode = cpu_to_le16(0700);

	pi->aeon_ino = de->ino;
	pi->parent_ino = parent->aeon_ino;
	pi->i_pinode_addr = parent->i_inode_addr;
	pi->i_dentry_addr = de->d_dentry_addr;
	pi->i_inode_addr = de->d_inode_addr;
	pi->valid = 1;
	pi->persisted = 1;
	aeon_update_inode_csum(pi);
}

static int pi_has_valid_de_addr(struct super_block *sb, struct aeon_inode *pi)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long last = sbi->last_addr;
	u64 addr = pi->i_dentry_addr;

	return (0 < addr && addr <= last);
}

static int de_has_valid_pi_addr(struct super_block *sb, struct aeon_dentry *de)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long last = sbi->last_addr;
	u64 addr = de->d_inode_addr;

	return (0 < addr && addr <= last);
}

static int de_has_valid_de_addr(struct super_block *sb, struct aeon_dentry *de)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long last = sbi->last_addr;
	u64 addr = de->d_dentry_addr;

	return (0 < addr && addr <= last);
}

static int aeon_lookup_dentry(struct aeon_sb_info *sbi, struct aeon_inode *pi,
			      struct aeon_dentry **de)
{
	struct aeon_dentry *tmp;
	u64 addr;

	/*
	 * Access the dentry address safely thanks to
	 * confirm it before go into this function.
	 */
	addr = le64_to_cpu(pi->i_dentry_addr);
	tmp = (struct aeon_dentry *)((u64)sbi->virt_addr + addr);
	if (tmp->ino == pi->aeon_ino) {
		aeon_rebuild_dentry(tmp, *de, pi);
		*de = tmp;
		return 0;
	}

	return 0;
}

static int aeon_lookup_inode(struct aeon_sb_info *sbi, struct aeon_dentry *de,
			     struct aeon_inode **pi, struct aeon_inode *parent)
{
	struct aeon_inode *tmp;
	unsigned long ino;
	u64 pi_addr = 0;
	int err;

	ino = le32_to_cpu(de->ino);
	err = aeon_get_inode_address(sbi->sb, ino, &pi_addr, de);
	if (!err) {
		tmp = (struct aeon_inode *)pi_addr;
		aeon_rebuild_inode(tmp, de, parent);
		*pi = tmp;

		return 0;
	}

	return -1;
}

static unsigned long aeon_recover_child(struct super_block *sb,
					struct aeon_inode *p_pi,
					struct aeon_dentry *p_de,
					struct aeon_inode **c_pi,
					struct aeon_dentry **c_de, int err)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	if (err == PARENT_PERSIST) {
		/* return -1 means giving up recovering */
		//struct invalid_obj_queue *ioq;
		void *tmp;
		u64 addr;
		int err;

		/* recover from inode */
		addr = le64_to_cpu((*c_pi)->i_pinode_addr);
		tmp = (void *)((u64)sbi->virt_addr + addr);
		if ((struct aeon_inode *)tmp != p_pi)
			(*c_pi)->i_pinode_addr = p_pi->i_inode_addr;

		addr =  le64_to_cpu((*c_pi)->i_inode_addr);
		tmp = (void *)((u64)sbi->virt_addr + addr);
		if (unlikely((struct aeon_inode *)tmp != (*c_pi))) {
			addr = (u64)(*c_pi);
			(*c_pi)->i_inode_addr = addr - (u64)sbi->virt_addr;
		}

		if (pi_has_valid_de_addr(sb, *c_pi)) {
			addr = le64_to_cpu((*c_pi)->i_dentry_addr);
			tmp = (void *)((u64)sbi->virt_addr + addr);
			aeon_rebuild_dentry(tmp, *c_de, *c_pi);
			*c_de = (struct aeon_dentry *)tmp;
		}

		if (de_has_valid_pi_addr(sb, *c_de)) {
			addr = le64_to_cpu((*c_de)->d_inode_addr);
			tmp = (void *)((u64)sbi->virt_addr + addr);
			aeon_rebuild_inode(tmp, *c_de, p_pi);
			*c_pi = (struct aeon_inode *)tmp;
		}

		return 0;

		if (pi_has_valid_de_addr(sb, *c_pi)) {
			err = aeon_lookup_dentry(sbi, *c_pi, c_de);
			if (!err)
				return 0;
		}

		/* recover from dentry */
		if (de_has_valid_de_addr(sb, *c_de)) {
			err = aeon_lookup_inode(sbi, *c_de, c_pi, p_pi);
			if (err)
				return -1;
			else
				return 0;
		} else
			return -1;
	} else if (err == P_AND_C_INODE_PERSIST) {
		struct aeon_dentry *tmp;
		unsigned long ino;
		u64 addr;

		addr = le64_to_cpu((*c_pi)->i_dentry_addr);
		tmp = (struct aeon_dentry *)((u64)sbi->virt_addr + addr);

		ino = le32_to_cpu((*c_pi)->aeon_ino);
		aeon_info("Recover dentry (ino:%lu)\n", ino);

		aeon_rebuild_dentry(tmp, *c_de, *c_pi);
		*c_de = tmp;
	} else if (err == P_AND_C_DENTRY_PERSIST) {
		struct aeon_inode *tmp;
		unsigned long ino;
		u64 addr;

		addr = le64_to_cpu((*c_de)->d_inode_addr);
		tmp = (struct aeon_inode *)((u64)sbi->virt_addr + addr);

		ino = le32_to_cpu((*c_pi)->aeon_ino);
		aeon_info("Recover dentry (ino:%lu)\n", ino);

		aeon_rebuild_inode(tmp, *c_de, p_pi);
		*c_pi = tmp;
	} else
		aeon_err(sb, "%s\n", __func__);

	return 0;
}

static int aeon_check_num_entry(struct aeon_inode *pi,
				struct aeon_dentry_map *de_map)
{
	return le64_to_cpu(pi->i_links_count) != de_map->num_dentries;
}

static int insert_existing_list(struct aeon_sb_info *sbi,
				struct i_valid_child_list *ivcl)
{
	struct i_valid_list *ivl;

	list_for_each_entry(ivl, &sbi->ivl->i_valid_list, i_valid_list) {
		if (ivl->parent_ino == ivcl->parent_ino) {
			list_add_tail(&ivcl->i_valid_child_list,
				      &ivl->ivcl->i_valid_child_list);
			return 1;
		}
	}

	return 0;
}

static int insert_inode_to_validlist(struct super_block *sb, u64 addr,
				     u32 ino, u32 parent_ino)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct i_valid_list *ivl;
	struct i_valid_child_list *ivcl_init;
	struct i_valid_child_list *ivcl;
	int res;

	ivcl = kmalloc(sizeof(struct i_valid_child_list), GFP_KERNEL);
	if (!ivcl)
		return -ENOMEM;

	mutex_lock(&sbi->s_lock);

	ivcl->addr = addr;
	ivcl->ino = ino;
	ivcl->parent_ino = parent_ino;
	res = insert_existing_list(sbi, ivcl);
	if (res) {
		mutex_unlock(&sbi->s_lock);
		return 0;
	}

	ivl = kmalloc(sizeof(struct i_valid_list), GFP_KERNEL);
	if (!ivl) {
		kfree(ivcl);
		ivcl = NULL;
		mutex_unlock(&sbi->s_lock);
		return -ENOMEM;
	}

	ivcl_init = kmalloc(sizeof(struct i_valid_child_list), GFP_KERNEL);
	if (!ivcl_init) {
		kfree(ivcl);
		kfree(ivl);
		ivcl = NULL;
		ivl = NULL;
		mutex_unlock(&sbi->s_lock);
		return -ENOMEM;
	}

	ivl->ivcl = ivcl_init;
	INIT_LIST_HEAD(&ivl->ivcl->i_valid_child_list);

	ivl->parent_ino = parent_ino;

	list_add_tail(&ivcl->i_valid_child_list, &ivl->ivcl->i_valid_child_list);
	list_add_tail(&ivl->i_valid_list, &sbi->ivl->i_valid_list);

	mutex_unlock(&sbi->s_lock);
	return 0;
}

static void aeon_remove_inode_from_imemcache(struct super_block *sb)
{
}

static int aeon_recover_child_again(struct super_block *sb,
				    struct aeon_inode *pi, struct inode *inode,
				    struct aeon_dentry_map *de_map)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	struct aeon_dentry *tmp;
	struct aeon_dentry *found;
	struct aeon_inode *candidate;
	unsigned long lost;
	unsigned long index = 0;
	unsigned long blocknr;
	int i;
	int name_len;
	int err;
	u64 pi_addr = 0;
	u32 ino;
	u32 parent_ino = cpu_to_le32(pi->aeon_ino);

	return 0;
	lost = le64_to_cpu(pi->i_links_count) - de_map->num_dentries;
	while (lost || index < de_map->num_latest_dentry) {
		blocknr = de_map->block_dentry[index];
		for (i = 0; i < AEON_INTERNAL_ENTRY; i++) {
			tmp = (struct aeon_dentry *)((u64)sbi->virt_addr +
				(blocknr << AEON_SHIFT) + (i << AEON_D_SHIFT));

			name_len = tmp->name_len;
			if (0 >= name_len || name_len >= AEON_NAME_LEN)
				continue;

			if (tmp->name[name_len + 1] != '\0')
				continue;

			if (!strcmp(".", tmp->name) ||
			    !strcmp("..", tmp->name) || !strcmp("", tmp->name))
				continue;

			found = aeon_find_dentry(sb, NULL, inode,
						 tmp->name, name_len);
			if (found)
				continue;
			aeon_dbg("REBU %s\n", tmp->name);

			ino = le32_to_cpu(tmp->ino);

			err = aeon_get_inode_address(sb, ino, &pi_addr, tmp);
			if (err == -ENOENT)
				continue;

			aeon_dbg("0x%llx\n", pi_addr);
			candidate = (struct aeon_inode *)pi_addr;
			if (candidate->deleted == 1)
				continue;

			aeon_rebuild_inode(candidate, tmp, pi);

			err = insert_inode_to_validlist(sb, pi_addr,
							ino, parent_ino);
			if (err) {
				aeon_err(sb, "%s: %d\n", __func__, err);
				return err;
			}

			aeon_remove_inode_from_imemcache(sb);

			err = aeon_insert_dir_tree(sb, sih, tmp->name,
						   tmp->name_len, tmp);
			if (err)
				continue;

			add_block_entry(de_map, blocknr, NULL);
			de_map->num_dentries++;
			de_map->num_internal_dentries++;
			if (de_map->num_internal_dentries == AEON_INTERNAL_ENTRY)
				de_map->num_internal_dentries = 0;

			aeon_dbg("OK %s\n", tmp->name);
			lost--;
		}

		index++;
	}

	return 0;
}

int aeon_rebuild_dir_inode_tree(struct super_block *sb, struct aeon_inode *pi,
				u64 pi_addr, struct inode *inode)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	struct aeon_dentry_info *de_info;
	struct aeon_dentry_invalid *adi;
	struct aeon_dentry_map *de_map;
	struct aeon_dentry *parent_de;
	struct aeon_dentry *d = NULL;
	struct aeon_inode *child_pi;
	struct i_valid_list *ivl;
	struct i_valid_child_list *ivcl;
	u64 d_blocknr;
	u64 de_addr = 0;
	u32 parent_ino;
	bool first = true;
	int err;
	int p_state = NOT_FOUND;
	int c_state = NOT_FOUND;

	de_info = kzalloc(sizeof(struct aeon_dentry_info), GFP_KERNEL);
	if (!de_info)
		return -ENOMEM;
	adi = kzalloc(sizeof(struct aeon_dentry_invalid), GFP_KERNEL);
	if (!adi) {
		kfree(de_info);
		de_info = NULL;
		return -ENOMEM;
	}

	de_info->di = adi;
	sih->de_info = de_info;
	de_map = &de_info->de_map;
	de_map->num_dentries = 2;
	de_map->num_latest_dentry = 0;
	de_map->num_internal_dentries = 0;
	INIT_LIST_HEAD(&de_info->di->invalid_list);

	parent_ino = le32_to_cpu(pi->aeon_ino);

	if (list_empty(&sbi->ivl->i_valid_list))
		return 0;

	mutex_lock(&de_info->dentry_mutex);

	list_for_each_entry(ivl, &sbi->ivl->i_valid_list, i_valid_list) {
		if (ivl->parent_ino == parent_ino)
			goto found;
	}
	aeon_err(sb, "CANNOT FIND TARGET DIR\n");
	kfree(de_info);
	kfree(adi);
	de_info = NULL;
	adi = NULL;
	mutex_unlock(&de_info->dentry_mutex);
	return -ENOENT;

found:
	aeon_dbg("Rebuild directory %u\n", parent_ino);
	if (is_persisted_inode(pi))
		p_state |= P_INODE_PERIST;

	if (parent_ino == AEON_ROOT_INO) {
		p_state |= P_DENTRY_PERSIST;
		goto skip_get_dentry;
	}

	err = aeon_get_dentry_address(sb, pi, &de_addr);
	if (!err) {
		parent_de = (struct aeon_dentry *)de_addr;
		if (is_persisted_dentry(parent_de))
			p_state |= P_DENTRY_PERSIST;
	}

skip_get_dentry:
	err = aeon_check_parent_dir_state(p_state);
	if (err)
		aeon_dbg("future %d\n", err);

	list_for_each_entry(ivcl, &ivl->ivcl->i_valid_child_list,
			    i_valid_child_list) {

		c_state = p_state;

		child_pi = (struct aeon_inode *)ivcl->addr;
		if (is_persisted_inode(child_pi)) {
			aeon_dbg("pass1\n");
			c_state |= C_INODE_PERSIST;
		}

		err = aeon_get_dentry_address(sb, child_pi, &de_addr);
		if (!err || err == -EINVAL) {
			d = (struct aeon_dentry *)de_addr;
			if (is_persisted_dentry(d)) {
				aeon_dbg("pass2\n");
				c_state |= C_DENTRY_PERSIST;
			}
		}

		err = aeon_check_child(p_state, c_state);
		if (err) {
			aeon_dbg("child state %d\n", err);
			err = aeon_recover_child(sb, pi, parent_de,
						 &child_pi, &d, err);
			if (err)
				/* Discard inode object */
				continue;
		}

		aeon_dbg("d->name %s d->name_len %d dino %u iino %u\n",
			 d->name, d->name_len, le32_to_cpu(d->ino), le32_to_cpu(child_pi->aeon_ino));
		err = aeon_insert_dir_tree(sb, sih, d->name, d->name_len, d);
		if (err)
			return err;

		d_blocknr = le64_to_cpu(child_pi->i_dentry_addr) >> AEON_SHIFT;
		aeon_dbg("d_blocknr %llu\n", d_blocknr);
		add_block_entry(de_map, d_blocknr, &first);
		de_map->num_dentries++;
		de_map->num_internal_dentries++;
		if (de_map->num_internal_dentries == AEON_INTERNAL_ENTRY)
			de_map->num_internal_dentries = 0;
	}

	err = aeon_check_num_entry(pi, de_map);
	if (err) {
		aeon_dbg("link count %llu, num entries %lu\n",
			 le64_to_cpu(pi->i_links_count), de_map->num_dentries);
		aeon_recover_child_again(sb, pi, inode, de_map);
		pi->i_links_count = cpu_to_le64(de_map->num_dentries);
		aeon_dbg("Recover: link count %llu, num entries %lu\n",
			 le64_to_cpu(pi->i_links_count), de_map->num_dentries);
	}

	mutex_unlock(&de_info->dentry_mutex);

	return 0;
}

static unsigned int imem_cache_rebuild(struct aeon_sb_info *sbi,
				       struct inode_map *inode_map,
				       unsigned long blocknr, u32 start_ino,
				       unsigned int allocated,
				       unsigned long *next_blocknr,
				       int space, int cpu_id)
{
	struct aeon_inode *pi;
	struct imem_cache *im;
	struct imem_cache *init;
	struct i_valid_list *ivl;
	struct i_valid_list *ivl_init;
	struct i_valid_child_list *ivcl = NULL;
	struct i_valid_child_list *ivcl_init;
	struct aeon_region_table *art;
	u64 virt_addr = (u64)sbi->virt_addr + (blocknr << AEON_SHIFT);
	u32 ino = start_ino;
	u32 ino_off = sbi->cpus;
	int i;
	unsigned int count = 0;

	if (!inode_map->im) {
		init = kmalloc(sizeof(struct imem_cache), GFP_KERNEL);
		inode_map->im = init;
		INIT_LIST_HEAD(&inode_map->im->imem_list);
	}

	mutex_lock(&sbi->s_lock);
	if (!sbi->ivl || !sbi->ivl->ivcl) {
		ivl_init = kmalloc(sizeof(struct i_valid_list), GFP_KERNEL);
		sbi->ivl = ivl_init;
		INIT_LIST_HEAD(&sbi->ivl->i_valid_list);

		ivcl_init = kmalloc(sizeof(struct i_valid_child_list),
				    GFP_KERNEL);
		sbi->ivl->ivcl = ivcl_init;
		INIT_LIST_HEAD(&sbi->ivl->ivcl->i_valid_child_list);

	}
	mutex_unlock(&sbi->s_lock);

	art = AEON_R_TABLE(inode_map);

	for (i = space; i < AEON_I_NUM_PER_PAGE; i++) {
		u64 addr;

		addr = virt_addr + (i << AEON_I_SHIFT);
		pi = (struct aeon_inode *)addr;

		if (i == 1)
			*next_blocknr = le64_to_cpu(pi->i_next_inode_block);

		if (pi->valid && !pi->deleted && (count < allocated)) {
			u64 addr;

			if (ino != le32_to_cpu(pi->aeon_ino))
				goto next;

			addr = (u64)sbi->virt_addr + cpu_to_le64(pi->i_inode_addr);
			if ((u64)pi != addr)
				goto next;

			mutex_lock(&sbi->s_lock);
			count++;
			ivcl = kmalloc(sizeof(struct i_valid_child_list),
				       GFP_KERNEL);
			ivcl->addr = addr;
			ivcl->ino = le32_to_cpu(pi->aeon_ino);
			ivcl->parent_ino = le32_to_cpu(pi->parent_ino);
			if (insert_existing_list(sbi, ivcl)) {
				mutex_unlock(&sbi->s_lock);
				goto next;
			}

			ivl = kmalloc(sizeof(struct i_valid_list), GFP_KERNEL);
			ivl->parent_ino = le32_to_cpu(pi->parent_ino);

			ivcl_init = kmalloc(sizeof(struct i_valid_child_list),
					    GFP_KERNEL);
			ivl->ivcl = ivcl_init;
			INIT_LIST_HEAD(&ivl->ivcl->i_valid_child_list);

			list_add_tail(&ivcl->i_valid_child_list,
				      &ivl->ivcl->i_valid_child_list);
			list_add_tail(&ivl->i_valid_list,
				      &sbi->ivl->i_valid_list);
			mutex_unlock(&sbi->s_lock);
		} else {
			/* Recovering space that had been used */
			u32 i = le32_to_cpu(art->i_range_high);
			if (ino > (i * sbi->cpus + cpu_id))
				goto next;
			if (!pi->deleted)
				pi->deleted = 1;
			im = kmalloc(sizeof(struct imem_cache), GFP_KERNEL);
			im->ino = ino;
			im->addr = addr;
			im->head = im;
			im->independent = 1;
			list_add_tail(&im->imem_list,
				      &inode_map->im->imem_list);
		}
next:
		ino += ino_off;
	}

	return count;
}

static void do_aeon_rebuild_inode_cache(struct super_block *sb, int cpu_id)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct inode_map *inode_map = &sbi->inode_maps[cpu_id];
	struct aeon_region_table *art;
	unsigned long offset;
	unsigned long blocknr = 0;
	int ino = sbi->cpus + cpu_id;
	unsigned int allocated;
	unsigned int ret;
	int i;

	if (sbi->s_mount_opt & AEON_MOUNT_FORMAT)
		return;

	mutex_lock(&inode_map->inode_table_mutex);

	art = AEON_R_TABLE(inode_map);
	offset = ((u64)inode_map->i_table_addr -
			(u64)sbi->virt_addr) >> AEON_SHIFT;
	allocated = le64_to_cpu(art->allocated);

	/* the first page for inode contains inode_table
	 * so it leaves space of a inode size between head
	 * of page and firtst inode (last argument).
	 */
	ret = imem_cache_rebuild(sbi, inode_map, offset, ino,
				 allocated, &blocknr, 1, cpu_id);
	allocated -= ret;
	offset = blocknr;
	ino = ino + (AEON_I_NUM_PER_PAGE - 1) * sbi->cpus;

	for (i = 1; i < le32_to_cpu(art->i_num_allocated_pages) /
					AEON_PAGES_FOR_INODE; i++) {
		ret = imem_cache_rebuild(sbi, inode_map, offset, ino,
					 allocated, &blocknr, 0, cpu_id);
		allocated -= ret;
		offset = blocknr;
		ino = ino + (AEON_I_NUM_PER_PAGE) * sbi->cpus;
	}

	mutex_unlock(&inode_map->inode_table_mutex);
}

void aeon_rebuild_inode_cache(struct super_block *sb)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	int i;

	for (i = 0; i < sbi->cpus; i++)
		do_aeon_rebuild_inode_cache(sb, i);
}
