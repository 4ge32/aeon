#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/random.h>

#include "aeon.h"
#include "aeon_super.h"
#include "aeon_dir.h"
#include "aeon_extents.h"

#define FULL_PERSIST            14
#define P_INODE_PERSIST         8
#define C_INODE_PERSIST         4
#define C_DENTRY_PERSIST        2
#define PARENT_PERSIST          (P_INODE_PERSIST)
#define CHILD_PERSIST           (C_INODE_PERSIST | C_DENTRY_PERSIST)
#define P_AND_C_INODE_PERSIST   (PARENT_PERSIST | C_INODE_PERSIST)
#define P_AND_C_DENTRY_PERSIST  (PARENT_PERSIST | C_DENTRY_PERSIST)
#define NOT_FOUND               0

int fs_persisted = 1;

int aeon_rebuild_extenttree(struct super_block *sb,
			    struct aeon_inode *pi, struct inode *inode)
{
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	int entries = le16_to_cpu(aeh->eh_entries);

	aeon_dbgv("Rebuild file (inode %u)", le32_to_cpu(pi->aeon_ino));
	if (entries < PI_MAX_INTERNAL_EXTENT + 1)
		return 0;

	return aeon_rebuild_rb_extenttree(sb, inode, entries);
}

static int aeon_check_parent_dir_state(int state)
{
	if (state && PARENT_PERSIST)
		return 0;
	return state;
}

static int aeon_check_mdata(int p_state, int c_state)
{
	int state = p_state | c_state;

	if (state == FULL_PERSIST)
		return 0;
	else
		return state;
}

static int pi_has_valid_de_addr(struct super_block *sb, struct aeon_inode *pi)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	unsigned long last = sbi->last_addr;
	u64 addr = pi->i_dentry_addr;

	return (0 < addr && addr <= last);
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
	aeon_update_inode_csum(pi);
}

static unsigned long aeon_recover_child(struct super_block *sb,
					struct aeon_inode *p_pi,
					struct aeon_dentry *p_de,
					struct aeon_inode **c_pi,
					struct aeon_dentry **c_de, int err)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	if (fs_persisted)
		return 0;

	if (err == CHILD_PERSIST) {
		struct opaque_list *oq;

		mutex_lock(&sbi->s_lock);

		oq = kmalloc(sizeof(struct opaque_list), GFP_KERNEL);
		if (!oq)
			return -ENOMEM;

		oq->pi = *c_pi;
		oq->de = *c_de;
		list_add(&oq->opaque_list, &sbi->oq->opaque_list);

		mutex_unlock(&sbi->s_lock);

		/* Recover process is passed to again() after
		 * getting all directory entry candidate.
		 */
		return -1;
	} else if (err == PARENT_PERSIST) {
		/* return -1 means giving up recovering */
		void *tmp;
		u64 addr;

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

static int
aeon_check_and_recover_dir(struct super_block *sb, struct aeon_inode *pidir,
			   struct aeon_dentry *parent_de,
			   struct i_valid_list *ivl,
			   struct aeon_dentry_info *de_info, int *p_state)
{
	struct aeon_dentry_candidate *adc;
	struct aeon_inode *pi;
	struct aeon_dentry *d = NULL;
	struct i_valid_child_list *ivcl;
	u64 de_addr = 0;
	int c_state = NOT_FOUND;
	int ret = 0;
	int err;


	adc = kzalloc(sizeof(struct aeon_dentry_candidate), GFP_KERNEL);
	if (!adc)
		return -ENOMEM;
	de_info->adc = adc;
	INIT_LIST_HEAD(&de_info->adc->list);

	if (is_persisted_inode(pidir)) {
		aeon_dbgv("pass\n");
		*p_state |= P_INODE_PERSIST;
	}

	err = aeon_check_parent_dir_state(*p_state);
	if (err)
		aeon_dbg("FUTURE %d\n", err);

	aeon_dbgv("CANDIDATE\n");
	list_for_each_entry(ivcl, &ivl->ivcl->i_valid_child_list,
			    i_valid_child_list) {
		c_state = *p_state;

		pi = (struct aeon_inode *)ivcl->addr;
		if (is_persisted_inode(pi)) {
			aeon_dbgv("pass1\n");
			c_state |= C_INODE_PERSIST;
		}

		err = aeon_get_dentry_address(sb, pi, &de_addr);
		if (!err || err == -EINVAL) {
			d = (struct aeon_dentry *)de_addr;
			if (is_persisted_dentry(d)) {
				aeon_dbgv("pass2\n");
				c_state |= C_DENTRY_PERSIST;
			}
		}

		err = aeon_check_mdata(*p_state, c_state);
		if (err) {
			aeon_dbgv("child state %d\n", err);
			err = aeon_recover_child(sb, pidir, parent_de,
						 &pi, &d, err);
			if (err)
				/* Discard an inode object or restore it later */
				continue;
		}

		adc = kzalloc(sizeof(struct aeon_dentry_candidate), GFP_KERNEL);
		if (!adc)
			return -ENOMEM;

		adc->d = d;
		aeon_dbgv("d->name %s d->name_len %d dino %u pino %u\n",
			  d->name, d->name_len,
			  le32_to_cpu(d->ino), le32_to_cpu(pi->aeon_ino));
		list_add_tail(&adc->list, &de_info->adc->list);
		ret++;
	}

	if (list_empty(&de_info->adc->list)) {
		kfree((void *)de_info->adc);
		de_info->adc = NULL;
	}


	return ret;
}

static void add_block_entry(struct aeon_dentry_map *de_map, u64 blocknr)
{
	int i;

	if (de_map->first) {
		de_map->block_dentry[0] = blocknr;
		de_map->first = false;
		return;
	}

	for (i = 0; i <= de_map->num_latest_dentry; i++) {
		if (de_map->block_dentry[i] == blocknr)
			return;
	}

	de_map->block_dentry[++de_map->num_latest_dentry]
		= le64_to_cpu(blocknr);
}

static int
aeon_iterate_candidate(struct aeon_dentry *de, struct aeon_dentry_info *de_info)
{
	struct aeon_dentry_candidate *ca;
	struct aeon_dentry_candidate *dend = NULL;
	int found = 0;

	list_for_each_entry_safe(ca, dend, &de_info->adc->list, list) {
		if (ca->d == de) {
			list_del(&ca->list);
			kfree((void *)ca);
			found = 1;
			goto out;
		}
	}

out:
	return found;
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

static int
do_insert_to_validlist(struct super_block *sb, u64 addr,
		       u32 ino, u32 parent_ino, struct i_valid_list *ivl)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
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
	list_add_tail(&ivcl->i_valid_child_list, &ivl->ivcl->i_valid_child_list);

	mutex_unlock(&sbi->s_lock);
	return 0;
}

static void
init_lost_inode(struct super_block *sb, struct aeon_inode *pi, u32 ino,
		u32 d_addr_base, u32 p_addr_base, u32 i_addr_base)
{
	aeon_memunlock_inode(sb, pi);

	if (!pi->i_mode)
		pi->i_mode = cpu_to_le16(0700);
	pi->aeon_ino = cpu_to_le32(ino);
	pi->i_pinode_addr = cpu_to_le64(p_addr_base);
	pi->i_inode_addr = cpu_to_le64(i_addr_base);
	pi->i_dentry_addr = cpu_to_le64(d_addr_base);

	pi->valid = 1;

	aeon_update_inode_csum(pi);

	aeon_memlock_inode(sb, pi);
}

static int
insert_inode_to_validlist(struct super_block *sb, struct aeon_inode *pidir,
			  struct aeon_dentry *negative_dentry,
			  struct i_valid_list *ivl)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode *pi;
	struct inode_map *inode_map;
	struct imem_cache *im;
	int ino = le32_to_cpu(negative_dentry->ino);
	int cpu_id;
	int err;
	u64 addr = 0;
	u64 d_addr_base;
	u64 p_addr_base;
	u64 i_addr_base;

	cpu_id = ino % sbi->cpus;
	if (cpu_id >= sbi->cpus)
		cpu_id -= sbi->cpus;

	inode_map = aeon_get_inode_map(sb, cpu_id);

	mutex_lock(&inode_map->inode_table_mutex);

	list_for_each_entry(im, &inode_map->im->imem_list, imem_list) {
		if (im->ino == ino) {
			addr = im->addr;
			list_del(&im->imem_list);
			kfree((void *)im);
			im = NULL;
			goto out;
		}
	}
out:
	mutex_unlock(&inode_map->inode_table_mutex);

	if (!addr)
		return -ENOENT;

	pi = (struct aeon_inode *)addr;
	if (pi->deleted) {
		negative_dentry->valid = 0;
		return -ENOENT;
	}

	err = do_insert_to_validlist(sb, addr, ino,
				     le32_to_cpu(pidir->aeon_ino), ivl);
	if (err) {
		aeon_err(sb, "%s:%d\n", __func__, __LINE__);
		return err;
	}

	d_addr_base = (u64)negative_dentry - (u64)sbi->virt_addr;
	p_addr_base = (u64)pidir - (u64)sbi->virt_addr;
	i_addr_base = addr - (u64)sbi->virt_addr;
	negative_dentry->d_dentry_addr = d_addr_base;
	negative_dentry->d_pinode_addr = p_addr_base;
	negative_dentry->d_inode_addr = i_addr_base;

	init_lost_inode(sb, (struct aeon_inode *)addr, ino, d_addr_base,
			p_addr_base, i_addr_base);

	return 0;
}

static void update_dentry_map(struct aeon_dentry_map *de_map)
{
	de_map->num_dentries++;
	de_map->num_internal_dentries++;
	if (de_map->num_internal_dentries == AEON_INTERNAL_ENTRY)
		de_map->num_internal_dentries = 0;
}

static int
do_aeon_rebuild_dirtree(struct super_block *sb,
			struct aeon_inode_info_header *sih,
			int num_candidate_dentries,
			struct i_valid_list *ivl)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode *pidir = aeon_get_inode(sb, sih);
	struct aeon_dentry *d;
	struct aeon_dentry_info *de_info = sih->de_info;
	struct aeon_dentry_map *de_map = aeon_get_dentry_map(sb, sih);
	u64 i_dentry_tb;
	u64 next_block;
	int i;
	int err;

	i_dentry_tb = aeon_get_dentry_tb_head(sb, pidir);
	if (!i_dentry_tb) {
		/* TODO: Not happend? */
		AEON_ERR(1);
	}

	/* Skip dot and dotdot direntry */
	d = (struct aeon_dentry *)((u64)sbi->virt_addr +
				   (i_dentry_tb << AEON_SHIFT));
	next_block = le64_to_cpu(d->d_next_dentry_block);

	aeon_dbgv("num_candidate_dentries %d\n", num_candidate_dentries);
	i = 2;
	while (num_candidate_dentries > 0) {
		if (!i_dentry_tb)
			break;
		add_block_entry(de_map, i_dentry_tb);
		for (; i < AEON_INTERNAL_ENTRY; i++) {
			struct aeon_dentry_invalid *adi;
			int found;

			d = (struct aeon_dentry *)((u64)sbi->virt_addr +
						   (i_dentry_tb << AEON_SHIFT) +
						   (i << AEON_D_SHIFT));
			if (i == 0)
				next_block = d->d_next_dentry_block;
			if (!d->valid) {
reuse_space:
				adi = kmalloc(sizeof(struct aeon_dentry_invalid),
					      GFP_KERNEL);
				if (!adi) {
					aeon_err(sb,
						 "%s: Can't get memory...\n",
						 __func__);
					return -ENOMEM;
				}
				adi->d_addr = d;
				list_add_tail(&adi->invalid_list,
					      &de_info->di->invalid_list);
				goto next;
			}

			found = aeon_iterate_candidate(d, de_info);
			if (!found) {
				aeon_info("Get an orphan inode %u\n",
					  le32_to_cpu(d->ino));
				aeon_dbgv("! %s\n", d->name);
				err = insert_inode_to_validlist(sb, pidir,
								d, ivl);
				if (err == -ENOENT) {
					aeon_info("Discard %u\n",
						  le32_to_cpu(d->ino));
					d->valid = 0;
					goto reuse_space;
				} else if (err) {
					aeon_err(sb, "%s:%d\n",
						 __func__, __LINE__);
					return err;
				}
			}

			aeon_dbgv("d->name %s d->name_len %d dino %u\n",
				  d->name, d->name_len, le32_to_cpu(d->ino));
			err = aeon_insert_dir_tree(sb, sih,
						   d->name, d->name_len, d);
			if (err) {
				aeon_err(sb, "%s: insert_dir_tree\n", __func__);
				return err;
			}

			num_candidate_dentries--;
			update_dentry_map(de_map);
			continue;
next:
			de_map->num_internal_dentries++;
			if (num_candidate_dentries == 0)
				break;
		}
		i_dentry_tb = next_block;
		i = 0;
	}

	return 0;
}

static int aeon_check_pidir(struct aeon_inode *pi,
				struct aeon_dentry_map *de_map,
				int state)
{
	if (state == PARENT_PERSIST) {
		aeon_dbgv("Update links %llu to %lu\n",
			  le64_to_cpu(pi->i_links_count), de_map->num_dentries);
		pi->i_links_count = cpu_to_le64(de_map->num_dentries);
		return 0;
	}

	return -1;
}

static int
aeon_recover_child_again(struct super_block *sb, struct aeon_inode *pi,
			 struct inode *inode, struct aeon_dentry_map *de_map)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	struct opaque_list *oq;
	struct opaque_list *dend;
	unsigned long lost;
	unsigned long links;
	unsigned long entries;
	unsigned int candidate = 0;
	u64 paddr = (u64)pi - (u64)sbi->virt_addr;
	int err;

	list_for_each_entry(oq, &sbi->oq->opaque_list, opaque_list) {
		candidate++;
	}
	links = le64_to_cpu(pi->i_links_count);
	entries = de_map->num_dentries;

	if (links > candidate + entries) {
		aeon_info("Not enough candidate(%d) - update the num of links\n",
			  candidate);
		links = candidate + entries;
	} else if (links < candidate + entries) {
		aeon_info("More candidate than expected - update the num of links\n");
		links = candidate + entries;
		pi->i_links_count = cpu_to_le64(links);
	}

	lost = links - entries;
	aeon_info("let's recover %lu objs\n", lost);
	list_for_each_entry_safe(oq, dend, &sbi->oq->opaque_list, opaque_list) {
		struct aeon_inode *ca;
		struct aeon_dentry *de;
		unsigned blocknr;

		ca = oq->pi;
		de = oq->de;

		if (paddr != le64_to_cpu(ca->i_pinode_addr) ||
		    paddr != le64_to_cpu(de->d_pinode_addr))
			continue;

		aeon_dbg("d->name %s d->name_len %d dino %u iino %u\n",
			 de->name, de->name_len, le32_to_cpu(de->ino),
			 le32_to_cpu(pi->aeon_ino));
		err = aeon_insert_dir_tree(sb, sih, de->name, de->name_len, de);
		if (err) {
			aeon_err(sb, "%s: insert_dir_tree\n", __func__);
			return err;
		}

		blocknr = le64_to_cpu(pi->i_dentry_addr) >> AEON_SHIFT;
		add_block_entry(de_map, blocknr);
		update_dentry_map(de_map);

		list_del(&oq->opaque_list);
		kfree(oq);

		lost--;
		if (!lost)
			break;

	}

	aeon_update_inode_csum(pi);

	return 0;
}

int aeon_rebuild_dir_inode_tree(struct super_block *sb, struct aeon_inode *pi,
				u64 pi_addr, struct inode *inode)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	struct aeon_dentry_info *de_info;
	struct aeon_dentry_map *de_map;
	struct aeon_dentry *parent_de;
	struct aeon_dentry_invalid *adi;
	struct i_valid_list *ivl;
	u32 parent_ino;
	int err = -ENOMEM;
	int ca = 0; /* the number of candidate dentries */
	int p_state = NOT_FOUND;

	de_info = kzalloc(sizeof(struct aeon_dentry_info), GFP_KERNEL);
	if (!de_info)
		return -ENOMEM;
	adi = kzalloc(sizeof(struct aeon_dentry_invalid), GFP_KERNEL);
	if (!adi)
		goto out;

	de_info->di = adi;
	sih->de_info = de_info;
	de_map = &de_info->de_map;
	de_map->num_dentries = 2;
	de_map->num_latest_dentry = 0;
	de_map->num_internal_dentries = 2;
	de_map->first = true;
	INIT_LIST_HEAD(&de_info->di->invalid_list);

	parent_ino = le32_to_cpu(pi->aeon_ino);

	if (list_empty(&sbi->ivl->i_valid_list))
		return 0;

	mutex_lock(&de_info->dentry_mutex);

	/* TODO:
	 * Remove rebuilt ino from this list
	 */
	list_for_each_entry(ivl, &sbi->ivl->i_valid_list, i_valid_list) {
		if (ivl->parent_ino == parent_ino)
			goto found;
	}

	aeon_err(sb, "CANNOT FIND TARGET DIR %u\n", parent_ino);
	mutex_unlock(&de_info->dentry_mutex);
	err = -ENOENT;
	goto out1;

found:
	aeon_dbgv("Rebuild & check directory %u\n", parent_ino);

	ca = aeon_check_and_recover_dir(sb, pi, parent_de, ivl,
					de_info, &p_state);
	if (ca < 0)
		goto out1;

	aeon_dbgv("OBJECTS\n");
	err = do_aeon_rebuild_dirtree(sb, sih, ca, ivl);
	if (err)
		goto out1;

	aeon_dbgv("CHECK PIDIR\n");
	err = aeon_check_pidir(pi, de_map, p_state);
	if (err) {
		aeon_info("link count %llu, num entries %lu\n",
			  le64_to_cpu(pi->i_links_count), de_map->num_dentries);
		aeon_recover_child_again(sb, pi, inode, de_map);
		pi->i_links_count = cpu_to_le64(de_map->num_dentries);
		aeon_info("Recover: link count %llu, num entries %lu\n",
			  le64_to_cpu(pi->i_links_count), de_map->num_dentries);
	}

	if (de_map->num_internal_dentries == 0)
		de_map->num_internal_dentries = AEON_INTERNAL_ENTRY;

	aeon_dbgv("demap - num:latestblock:internal %lu:%u:%u",
		  de_map->num_dentries, de_map->num_latest_dentry,
		  de_map->num_internal_dentries);

	mutex_unlock(&de_info->dentry_mutex);

	return 0;
out1:
	kfree(de_info->di);
	de_info->di = NULL;
out:
	kfree(de_info);
	de_info = NULL;

	return err;
}

static unsigned int
imem_cache_rebuild(struct aeon_sb_info *sbi, struct inode_map *inode_map,
		   unsigned long blocknr, u32 start_ino,
		   unsigned int allocated,  unsigned long *next_blocknr,
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
	struct inode_map *inode_map = aeon_get_inode_map(sb, cpu_id);
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
