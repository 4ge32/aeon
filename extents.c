#include <linux/fs.h>

#include "aeon.h"
#include "aeon_extents.h"


static struct aeon_extent
*aeon_rb_search_extent(struct super_block *sb,
		       struct aeon_inode_info_header *sih, unsigned long offset)
{
	struct aeon_range_node *ret_node = NULL;
	struct aeon_extent *ret = NULL;
	bool found;

	found = aeon_find_range_node(&sih->rb_tree, offset, NODE_EXTENT, &ret_node);
	if (found)
		ret = ret_node->extent;

	return ret;
}

u64 aeon_pull_extent_addr(struct super_block *sb,
			  struct aeon_inode_info_header *sih,
			  int index)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	unsigned long blocknr;
	u64 addr;
	int num_exblock;
	int internal_index;

	if (index < PI_MAX_INTERNAL_EXTENT) {
		addr = (u64)&pi->ae[index];
		return addr;
	}

	internal_index = index - PI_MAX_INTERNAL_EXTENT;
	num_exblock = internal_index / AEON_EXTENT_PER_PAGE;
	if (num_exblock < 0 || PI_MAX_EXTERNAL_EXTENT <= num_exblock) {
		aeon_err(sb, "out of bounds in extent header\n");
		return 0;
	}
	blocknr = le64_to_cpu(aeh->eh_extent_blocks[num_exblock]);
	internal_index %= AEON_EXTENT_PER_PAGE;

	addr = (u64)sbi->virt_addr + (blocknr << AEON_SHIFT) +
				(internal_index << AEON_E_SHIFT);
	return addr;
}

static
struct aeon_extent *do_aeon_get_extent_on_pmem(struct super_block *sb,
					       struct aeon_inode_info_header *sih)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	unsigned long blocknr = 0;
	int entries;
	int external_entries;
	int num_exblock;
	u64 addr;

	entries = le16_to_cpu(aeh->eh_entries);
	if (entries < PI_MAX_INTERNAL_EXTENT)
		return &pi->ae[entries];

	entries = entries - PI_MAX_INTERNAL_EXTENT;
	num_exblock = le64_to_cpu(pi->i_exblocks) - 2;
	external_entries = entries % AEON_EXTENT_PER_PAGE;

	if (!external_entries) {
		unsigned long new_blocknr = 0;
		int next_num_exblock = num_exblock + 1;

		if (next_num_exblock == PI_MAX_EXTERNAL_EXTENT) {
			aeon_err(sb, "no space in extent header\n");
			return NULL;
		}

		new_blocknr = aeon_get_new_extents_block(sb);
		if (new_blocknr <= 0) {
			aeon_err(sb, "%s\n", __func__);
			return NULL;
		}

		aeh->eh_extent_blocks[next_num_exblock] = cpu_to_le64(new_blocknr);
		pi->i_exblocks++;
		num_exblock = next_num_exblock;
	}

	blocknr = le64_to_cpu(aeh->eh_extent_blocks[num_exblock]);
	addr = (u64)sbi->virt_addr + (blocknr << AEON_SHIFT) +
					(external_entries << AEON_E_SHIFT);

	return (struct aeon_extent *)addr;
}

static
struct aeon_extent *aeon_linear_search_extent(struct super_block *sb,
					      struct aeon_inode_info_header *sih,
					      struct aeon_extent_header *aeh,
					      unsigned long iblock)
{
	struct aeon_extent *ae;
	unsigned int offset;
	int length;
	int entries;
	int index = 0;
	u64 addr;


	read_lock(&sih->i_meta_lock);
	entries = le16_to_cpu(aeh->eh_entries);
	while (entries > 0) {
		addr = aeon_pull_extent_addr(sb, sih, index);
		if (!addr) {
			read_unlock(&sih->i_meta_lock);
			return NULL;
		}
		ae = (struct aeon_extent *)addr;

		length = le16_to_cpu(ae->ex_length);
		offset = le16_to_cpu(ae->ex_offset);
		if (offset <= iblock && iblock < offset + length) {
			read_unlock(&sih->i_meta_lock);
			return (struct aeon_extent *)addr;
		}

		index++;
		entries--;
	}
	read_unlock(&sih->i_meta_lock);

	return NULL;
}

struct aeon_extent
*aeon_search_extent(struct super_block *sb,
		    struct aeon_inode_info_header *sih, unsigned long iblock)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh;
	struct aeon_extent *ret = NULL;
	int entries;

	if (!pi->i_exblocks)
		goto out;

	aeh = aeon_get_extent_header(pi);

	entries = le16_to_cpu(aeh->eh_entries);
	if (!entries)
		goto out;

#ifndef USE_RB
	ret = aeon_linear_search_extent(sb, sih, aeh, iblock);
#else
	if (entries < PI_MAX_INTERNAL_EXTENT + 1) {
		ret = aeon_linear_search_extent(sb, sih, aeh, iblock);
		goto out;
	}
	ret = aeon_rb_search_extent(sb, sih, iblock);
#endif
out:
	return ret;
}

static struct aeon_extent
*aeon_get_new_extent(struct super_block *sb, struct aeon_inode_info_header *sih)
{
	struct aeon_extent *ret;

	write_lock(&sih->i_meta_lock);
	ret =  do_aeon_get_extent_on_pmem(sb, sih);
	write_unlock(&sih->i_meta_lock);

	return ret;
}

static int
do_aeon_insert_extenttree(struct rb_root *tree, struct aeon_range_node *new_node)
{
	int ret;

	ret = aeon_insert_range_node(tree, new_node, NODE_EXTENT);
	if (ret)
		aeon_dbg("ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

static int
aeon_build_new_rb_extent_tree(struct super_block *sb,
			      struct aeon_inode_info_header *sih)
{
	struct aeon_range_node *node = NULL;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	int ret;
	int i;

	for (i = 0; i < PI_MAX_INTERNAL_EXTENT; i++) {
		node = aeon_alloc_extent_node(sb);
		if (!node)
			return -ENOMEM;
		node->offset = le32_to_cpu(pi->ae[i].ex_offset);
		node->length = le16_to_cpu(pi->ae[i].ex_length);
		node->extent = &pi->ae[i];

		ret = do_aeon_insert_extenttree(&sih->rb_tree, node);
		if (ret) {
			aeon_free_extent_node(node);
			return ret;
		}
	}

	return 0;
}

static int
aeon_insert_extenttree(struct super_block *sb,
		       struct aeon_inode_info_header *sih,
		       struct aeon_extent_header *aeh, struct aeon_extent *ae)
{
#ifndef USE_RB
	return 0;
#else
	struct aeon_range_node *node = NULL;
	int entries;
	int err;

	entries = le16_to_cpu(aeh->eh_entries);
	/* Do not use a tree while there are few extents */
	if (entries < PI_MAX_INTERNAL_EXTENT + 1) {
		return 0;
	}

	if (entries == PI_MAX_INTERNAL_EXTENT + 1) {
		err = aeon_build_new_rb_extent_tree(sb, sih);
		if (err) {
			aeon_err(sb, "%s: failed to build a tree\n", __func__);
			return err;
		}
	}

	node = aeon_alloc_extent_node(sb);
	if (!node)
		return -ENOMEM;
	node->offset = le32_to_cpu(ae->ex_offset);
	node->length = le16_to_cpu(ae->ex_length);
	node->extent = ae;

	err = do_aeon_insert_extenttree(&sih->rb_tree, node);
	if (err) {
		aeon_free_extent_node(node);
		aeon_err(sb, "%s: %d\n", __func__, err);
		return err;
	}

	return 0;
#endif
}

int
aeon_update_extent(struct super_block *sb, struct inode *inode,
		   unsigned blocknr, unsigned long offset, int num_blocks)
{
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	struct aeon_extent *ae;
	int err = -ENOSPC;

	ae = aeon_get_new_extent(sb, sih);
	if (!ae) {
		aeon_err(sb, "can't expand file more\n");
		return err;
	}

	read_lock(&sih->i_meta_lock);
	ae->ex_index = aeh->eh_entries;
	ae->ex_length = cpu_to_le16(num_blocks);
	ae->ex_block = cpu_to_le64(blocknr);
	ae->ex_offset = cpu_to_le32(offset);
	aeh->eh_blocks += cpu_to_le16(num_blocks);
	aeh->eh_entries++;

	pi->i_blocks = aeh->eh_blocks * 8;
	inode->i_blocks = le32_to_cpu(pi->i_blocks);

	err = aeon_insert_extenttree(sb, sih, aeh, ae);
	if (err) {
		read_unlock(&sih->i_meta_lock);
		return err;
	}

	read_unlock(&sih->i_meta_lock);

	return 0;
}

static int
aeon_remove_extenttree(struct super_block *sb,
		       struct aeon_inode_info_header *sih, unsigned long offset)
{
	struct aeon_extent *ae;
	struct aeon_range_node *ret_node = NULL;
	bool found = false;

#ifndef USE_RB
	return 0;

#else
	found = aeon_find_range_node(&sih->rb_tree, offset, NODE_EXTENT, &ret_node);
	if (!found) {
		aeon_err(sb, "%s target not found: %lu\n", __func__, offset);
		return -EINVAL;
	}

	ae = ret_node->extent;
	rb_erase(&ret_node->node, &sih->rb_tree);
	aeon_free_extent_node(ret_node);

	return 0;
#endif
}

int
aeon_delete_extenttree(struct super_block *sb,
		       struct aeon_inode_info_header *sih)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	struct aeon_extent *ae;
	unsigned long freed_blocknr;
	int entries;
	int index = 0;
	int num;
	int err;
	int i;
	u64 addr;

	/* TODO:
	 * Free allocated extent pages if the inode has
	 */
	entries = le16_to_cpu(aeh->eh_entries);
	while (entries > 0) {
		addr = aeon_pull_extent_addr(sb, sih, index);
		if (!addr) {
			aeon_err(sb, "addr 0x%llx", addr);
			return -EINVAL;
		}
		ae = (struct aeon_extent *)addr;

		freed_blocknr = le64_to_cpu(ae->ex_block);
		num = le16_to_cpu(ae->ex_length);
		ae->ex_block = 0;
		ae->ex_length = 0;
		ae->ex_offset = 0;
		if (freed_blocknr == 0)
			goto next;
		err = aeon_insert_blocks_into_free_list(sb, freed_blocknr, num, 0);
		if (err) {
			aeon_err(sb, "%s: insert blocks into free list\n", __func__);
			return -EINVAL;
		}

next:
		index++;
		entries--;
	}

	for (i = 0; i < PI_MAX_EXTERNAL_EXTENT; i++) {
		freed_blocknr = aeh->eh_extent_blocks[i];
		if (!freed_blocknr)
			goto end;

		err = aeon_insert_blocks_into_free_list(sb, freed_blocknr, 1, 0);
		if (err) {
			aeon_err(sb, "%s: insert blocks into free list\n", __func__);
			return -EINVAL;
		}
	}

end:
	aeh->eh_entries = 0;

#ifdef USE_RB
	aeon_destroy_range_node_tree(sb, &sih->rb_tree);
#endif

	return 0;
}

int
aeon_cutoff_extenttree(struct super_block *sb,
		       struct aeon_inode_info_header *sih,
		       struct aeon_inode *pi, int remaining, int index)
{
	struct aeon_extent *ae;
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	unsigned long blocknr;
	unsigned long offset;
	int length;
	int err;
	u64 addr;

	/* TODO:
	 * Preparing for Reuse freed region
	 */
	while (remaining > 0) {
		addr = aeon_pull_extent_addr(sb, sih, index);
		if (!addr) {
			aeon_err(sb, "failed to get expected extent\n");
			return -EINVAL;
		}
		ae = (struct aeon_extent *)addr;
		blocknr = le64_to_cpu(ae->ex_block);
		length = le16_to_cpu(ae->ex_length);
		offset = le16_to_cpu(ae->ex_offset);

		err = aeon_insert_blocks_into_free_list(sb, blocknr, length, 0);
		if (err) {
			aeon_err(sb, "%s: insert blocks into free list\n", __func__);
			return -EINVAL;
		}
		err = aeon_remove_extenttree(sb, sih, offset);
		if (err) {
			aeon_err(sb, "%s: remove blocks from a tree\n", __func__);
			return -EINVAL;
		}

		aeh->eh_entries--;
		ae->ex_block = 0;
		ae->ex_length = 0;
		ae->ex_offset = 0;

		index++;
		remaining--;
	}

	return 0;
}
