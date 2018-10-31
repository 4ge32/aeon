#include <linux/fs.h>
#include <linux/slab.h>

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

	if (*first) {
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

static void aeon_recover_child(struct super_block *sb,
			       struct aeon_inode *p_pi,
			       struct aeon_dentry *p_de,
			       struct aeon_inode *c_pi,
			       struct aeon_dentry *c_de, int err)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long i_blocknr_from_pi;
	unsigned long i_blocknr_from_de;
	unsigned long blocknr;

	if (err == PARENT_PERSIST) {
		aeon_info("TOP\n");
		i_blocknr_from_pi = le64_to_cpu(c_pi->i_inode_block);
		i_blocknr_from_de = le64_to_cpu(c_de->i_blocknr);

	} else if (err == P_AND_C_INODE_PERSIST) {
		struct aeon_dentry *test;
		unsigned long offset;
		u64 inode_blocknr;
		unsigned long ino;
		unsigned long internal_ino;
		int cpu_id;

		blocknr = le64_to_cpu(c_pi->i_dentry_block);
		offset = le32_to_cpu(c_pi->i_d_internal_off);

		test = (struct aeon_dentry *)((u64)sbi->virt_addr +
			(blocknr << AEON_SHIFT) + (offset << AEON_D_SHIFT));

		if (c_de != test)
			c_de = test;

		ino = le32_to_cpu(c_pi->aeon_ino);

		cpu_id = ino % sbi->cpus;
		internal_ino = ((ino - cpu_id) / sbi->cpus) %
						AEON_I_NUM_PER_PAGE;
		inode_blocknr = ((u64)c_pi - (u64)sbi->virt_addr) >> AEON_SHIFT;

		c_de->internal_offset = c_pi->i_d_internal_off;
		c_de->global_offset = c_pi->i_d_global_off;
		c_de->i_blocknr = cpu_to_le64(inode_blocknr);
		c_de->valid = 1;
		c_de->persisted = 1;
		aeon_update_dentry_csum(c_de);
	} else if (err == P_AND_C_DENTRY_PERSIST) {
		aeon_info("DOWN\n");
	} else
		aeon_err(sb, "%s\n", __func__);
}

int aeon_rebuild_dir_inode_tree(struct super_block *sb, struct aeon_inode *pi,
				u64 pi_addr, struct aeon_inode_info_header *sih)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_dentry_info *de_info;
	struct aeon_dentry_invalid *adi;
	struct aeon_dentry_map *de_map;
	struct aeon_dentry *parent_de;
	struct aeon_dentry *d;
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
	aeon_dbg("Rebuild %u directory\n", parent_ino);
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

		child_pi = (struct aeon_inode *)ivcl->addr;
		if (is_persisted_inode(child_pi)) {
			aeon_dbg("pass1\n");
			c_state |= C_INODE_PERSIST;
		}

		err = aeon_get_dentry_address(sb, child_pi, &de_addr);
		if (!err) {
			d = (struct aeon_dentry *)de_addr;
			if (is_persisted_dentry(d)) {
				aeon_dbg("pass2\n");
				c_state |= C_DENTRY_PERSIST;
			}
		} else {
			/* discard this inode */
			aeon_info("Delete entries not completely created\n");
			continue;
		}

		err = aeon_check_child(p_state, c_state);
		if (err) {
			aeon_dbg("child state %d\n", err);
			aeon_recover_child(sb, pi, parent_de, child_pi, d, err);
		}

		err = aeon_insert_dir_tree(sb, sih, d->name, d->name_len, d);
		if (err)
			return err;

		d_blocknr = le64_to_cpu(child_pi->i_dentry_block);
		add_block_entry(de_map, d_blocknr, &first);
		de_map->num_dentries++;
		de_map->num_internal_dentries++;
		if (de_map->num_internal_dentries == AEON_INTERNAL_ENTRY)
			de_map->num_internal_dentries = 0;
	}

	mutex_unlock(&de_info->dentry_mutex);

	return 0;
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

	if (!sbi->ivl || !sbi->ivl->ivcl) {
		ivl_init = kmalloc(sizeof(struct i_valid_list), GFP_KERNEL);
		sbi->ivl = ivl_init;
		INIT_LIST_HEAD(&sbi->ivl->i_valid_list);

		ivcl_init = kmalloc(sizeof(struct i_valid_child_list),
				    GFP_KERNEL);
		sbi->ivl->ivcl = ivcl_init;
		INIT_LIST_HEAD(&sbi->ivl->ivcl->i_valid_child_list);

	}

	art = AEON_R_TABLE(inode_map);

	for (i = space; i < AEON_I_NUM_PER_PAGE; i++) {
		u64 addr;

		addr = virt_addr + (i << AEON_I_SHIFT);
		pi = (struct aeon_inode *)addr;

		if (i == 1)
			*next_blocknr = le64_to_cpu(pi->i_next_inode_block);

		if (pi->valid && (count < allocated)) {
			if (ino != le32_to_cpu(pi->aeon_ino))
				goto next;

			count++;
			ivcl = kmalloc(sizeof(struct i_valid_child_list),
				       GFP_KERNEL);
			ivcl->addr = addr;
			ivcl->ino = le32_to_cpu(pi->aeon_ino);
			ivcl->parent_ino = le32_to_cpu(pi->parent_ino);
			if (insert_existing_list(sbi, ivcl)) {
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
		} else {
			/* Recovering space that had been used */
			u32 i = le32_to_cpu(art->i_range_high);
			if (ino > (i * sbi->cpus + cpu_id))
				goto next;
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
	int ino = AEON_INODE_START + cpu_id;
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
