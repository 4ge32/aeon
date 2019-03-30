#include <linux/fs.h>
#include <linux/slab.h>

#include "aeon.h"
#include "aeon_super.h"
#include "aeon_extents.h"
#include "aeon_balloc.h"

typedef struct _extentIterator{
	struct super_block *sb;
	struct aeon_inode_info_header *sih;
	struct aeon_extent_header *aeh;
	struct aeon_extent_middle_header *h_header;
	struct aeon_extent_middle_header *c_header;
	struct aeon_extent_middle_header *l_header;
	struct aeon_extent *curr;
	struct aeon_extent *last;
	int index;
	bool (*hasNext)(struct _extentIterator *);
	struct aeon_extent *(*getCurrExtent)(struct _extentIterator *);
	struct aeon_extent *(*getLastExtent)(struct _extentIterator *);
	struct _extentIterator *(*next)(struct _extentIterator *);
	u64 aeon_head;
	bool deleteExtentsBlock;
} Iterator;

static bool
hasNext(Iterator *i)
{
	return i->curr != i->getLastExtent(i) ? true : false;
}

/*TODO: Remove "if statement" in below two funcs if it can */
static struct aeon_extent
*_Curr(Iterator *itr)
{
	if (!itr->c_header)
		return NULL;
	return (struct aeon_extent *)((u64)itr->c_header +
				      (itr->index<<AEON_E_SHIFT));
}

static struct aeon_extent
*_Last(Iterator *itr)
{
	if (!itr->l_header)
		return NULL;
	return (struct aeon_extent *)((u64)itr->l_header +
		((le16_to_cpu(itr->l_header->em_entries)-1)<<AEON_E_SHIFT));
}

static void
__free_extents_blocks(u64 freed_addr, Iterator *itr)
{
	struct super_block *sb = itr->sb;
	unsigned long blocknr;
	int err;

	blocknr = (freed_addr - AEON_HEAD(sb)) >> AEON_SHIFT;
	err = aeon_insert_blocks_into_free_list(sb, blocknr, 1, 0);
	if (err)
		BUG();
}

static void
__NextRegion(Iterator *itr)
{
	u64 freed = (u64)itr->c_header;
	u64 addr = le64_to_cpu(itr->c_header->em_next_addr);
	itr->c_header = (void *)(itr->aeon_head + addr);
	itr->index = 1;

	if (addr && itr->deleteExtentsBlock)
		__free_extents_blocks(freed, itr);
}

static Iterator
*_Next(Iterator *itr)
{
	itr->curr = itr->getCurrExtent(itr);
	itr->index++;
	if (!(itr->index % AEON_EXTENT_PER_PAGE))
		__NextRegion(itr);
	return itr;
}

static Iterator
*initialize(struct super_block *sb,
	    struct aeon_inode_info_header *sih, bool delete_extents_blocks)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);

	Iterator *itr = kmalloc(sizeof(Iterator), GFP_KERNEL);
	itr->sb = sb;
	itr->sih = sih;
	itr->aeon_head = AEON_HEAD(sb);
	itr->aeh = aeon_get_extent_header(pi);
	itr->h_header = itr->c_header = aeon_get_extent_first_mheader(sb, pi);
	itr->l_header = aeon_get_extent_mheader(sb, pi);
	itr->index = 1;
	itr->getCurrExtent = _Curr;
	itr->getLastExtent = _Last;
	itr->next = _Next;
	itr->hasNext = hasNext;
	itr->deleteExtentsBlock = delete_extents_blocks;
	if (!itr->h_header) {
		itr->curr = NULL;
		itr->l_header = NULL;
	} else {
		itr->curr = itr->getCurrExtent(itr);
		itr->last = itr->getLastExtent(itr);
	}

	return itr;
}

static Iterator
*init_lookup(struct super_block *sb, struct aeon_inode_info_header *sih)
{
	return initialize(sb, sih, false);
}

static Iterator
*init_delete(struct super_block *sb, struct aeon_inode_info_header *sih)
{
	return initialize(sb, sih, true);
}

static void
finalize(Iterator *itr)
{
	kfree(itr);
}

static void
final_lookup(Iterator *itr)
{
	finalize(itr);
}

static void
final_delete(Iterator *itr)
{
	itr->aeh->eh_entries = 0;
	if (itr->l_header)
		__free_extents_blocks((u64)itr->l_header, itr);
	aeon_destroy_range_node_tree(itr->sb, &itr->sih->rb_tree);
	finalize(itr);
}

static struct aeon_extent
*aeon_rb_search_extent(struct super_block *sb,
		       struct aeon_inode_info_header *sih, unsigned long offset)
{
	struct aeon_range_node *ret_node = NULL;
	struct aeon_extent *ret = NULL;
	bool found;

	found = aeon_find_range_node(&sih->rb_tree, offset,
				     NODE_EXTENT, &ret_node);
	if (found)
		ret = ret_node->extent;

	return ret;
}

static u64
aeon_pull_extent_addr(struct super_block *sb,
		      struct aeon_inode_info_header *sih, int index)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	u64 addr;

	if (index < PI_MAX_INTERNAL_EXTENT) {
		addr = (u64)&pi->ae[index];
		return addr;
	}

	BUG();
}

static struct aeon_extent
*aeon_linear_search_extent(struct super_block *sb,
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
	unsigned long all_entries;

	if (!pi->i_exblocks)
		goto out;

	aeh = aeon_get_extent_header(pi);

	all_entries = le16_to_cpu(aeh->eh_entries);
	if (!all_entries)
		goto out;

	if (all_entries < PI_MAX_INTERNAL_EXTENT + 1) {
		ret = aeon_linear_search_extent(sb, sih, aeh, iblock);
		goto out;
	}
	ret = aeon_rb_search_extent(sb, sih, iblock);
out:
	return ret;
}

static int
aeon_expand_extents_block(struct super_block *sb,
			  struct aeon_extent_header *aeh)
{
	struct aeon_extent_middle_header *aemh;
	u64 addr;

	addr = aeon_get_new_extents_block_addr(sb);
	if (!addr) {
		aeon_err(sb, "%s: failed to get new blocks\n", __func__);
		return -ENOSPC;
	}

	aeh->eh_first_block_addr = aeh->eh_cur_block_addr = le64_to_cpu(addr);
	aemh = (struct aeon_extent_middle_header *)(AEON_HEAD(sb) + addr);
	aeon_init_extent_middle_header(aemh);

	return 0;
}

static int
aeon_expand_extents_block2(struct super_block *sb,
			   struct aeon_extent_header *aeh,
			   struct aeon_extent_middle_header *aemh)
{
	u64 addr;

	addr = aeon_get_new_extents_block_addr(sb);
	if (!addr) {
		aeon_err(sb, "failed to get new blocks\n");
		return -ENOSPC;
	}

	aeh->eh_cur_block_addr = le64_to_cpu(addr);
	aemh->em_next_addr = le64_to_cpu(addr);
	aemh = (struct aeon_extent_middle_header *)(AEON_HEAD(sb) + addr);
	aeon_init_extent_middle_header(aemh);

	return 0;
}

static struct aeon_extent
*do_aeon_get_extent_on_pmem(struct super_block *sb,
			    struct aeon_inode_info_header *sih)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	struct aeon_extent_middle_header *aemh;
	unsigned long all_entries;
	int per_entries;
	int external_spaces;
	int err;
	u64 addr;

	all_entries = le64_to_cpu(aeh->eh_entries);
	if (all_entries < PI_MAX_INTERNAL_EXTENT) {
		aeh->eh_entries++;
		return &pi->ae[all_entries];
	}

	/*TODO: be efficient from here */

	if (!le64_to_cpu(aeh->eh_first_block_addr)) {
		err = aeon_expand_extents_block(sb, aeh);
		if (err)
			return NULL;
	}

	aemh = aeon_get_extent_mheader(sb, pi);
	per_entries = le16_to_cpu(aemh->em_entries);
	external_spaces = per_entries % AEON_EXTENT_PER_PAGE;

	if (!external_spaces) {
		err = aeon_expand_extents_block2(sb, aeh, aemh);
		if (err)
			return NULL;
		aemh = aeon_get_extent_mheader(sb, pi);
		external_spaces = 1;
	}

	addr = (u64)aemh + (external_spaces<<AEON_E_SHIFT);
	aemh->em_entries++;
	aeh->eh_entries++;
	return (struct aeon_extent *)addr;
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
	int err;
	int i;

	for (i = 0; i < PI_MAX_INTERNAL_EXTENT; i++) {
		node = aeon_alloc_extent_node(sb);
		if (!node)
			return -ENOMEM;

		node->offset = le32_to_cpu(pi->ae[i].ex_offset);
		node->length = le16_to_cpu(pi->ae[i].ex_length);
		node->extent = &pi->ae[i];

		err = do_aeon_insert_extenttree(&sih->rb_tree, node);
		if (err) {
			aeon_free_extent_node(node);
			return err;
		}

	}

	return 0;
}

static int
aeon_insert_extenttree(struct super_block *sb,
		       struct aeon_inode_info_header *sih,
		       struct aeon_extent_header *aeh, struct aeon_extent *ae)
{
	struct aeon_range_node *node = NULL;
	unsigned long entries;
	int err;

	entries = le32_to_cpu(aeh->eh_entries);
	if (entries < PI_MAX_INTERNAL_EXTENT + 1)
		return 0;

	if (le32_to_cpu(aeh->eh_blocks) == INT_MAX)
		return -ENOSPC;

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
}

int
aeon_update_extent(struct super_block *sb, struct inode *inode,
		   unsigned long blocknr, unsigned long offset, int num_blocks)
{
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	struct aeon_extent *ae;
	//unsigned long next;
	int err = -ENOSPC;

	/* TODO: separate this processing */
//	if (le16_to_cpu(aeh->eh_entries)) {
//		ae = aeon_get_prev_extent(aeh);
//		if (!ae)
//			goto new_alloc;
//
//		if (le16_to_cpu(ae->ex_length) >= SHRT_MAX)
//			goto new_alloc;
//
//		next = le64_to_cpu(ae->ex_block) + le16_to_cpu(ae->ex_length);
//		if (next != blocknr)
//			goto new_alloc;
//
//		write_lock(&sih->i_meta_lock);
//
//		ae->ex_length += cpu_to_le16(num_blocks);
//		aeh->eh_blocks += cpu_to_le16(num_blocks);
//
//		write_unlock(&sih->i_meta_lock);
//
//		return 0;
//	}
//
//new_alloc:
	ae = aeon_get_new_extent(sb, sih);
	if (!ae) {
		aeon_err(sb, "can't expand file more\n");
		return err;
	}

	write_lock(&sih->i_meta_lock);

	ae->ex_index = aeh->eh_entries;
	ae->ex_length = cpu_to_le16(num_blocks);
	ae->ex_block = cpu_to_le64(blocknr);
	ae->ex_offset = cpu_to_le32(offset);
	aeh->eh_blocks += cpu_to_le16(num_blocks);
	//aeh->eh_prev_extent = cpu_to_le64(ae);

	pi->i_blocks = aeh->eh_blocks * 8;
	inode->i_blocks = le32_to_cpu(pi->i_blocks);

	err = aeon_insert_extenttree(sb, sih, aeh, ae);
	if (err) {
		write_unlock(&sih->i_meta_lock);
		return err;
	}

	write_unlock(&sih->i_meta_lock);

	return 0;
}

static int
free_internal_extents(struct super_block *sb,
		      struct aeon_inode_info_header *sih)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	struct aeon_extent *ae;
	unsigned long blocknr;
	int length;
	u64 addr;
	int i;
	int err;
	int max_internal = PI_MAX_INTERNAL_EXTENT;
	int entire_entries = le32_to_cpu(aeh->eh_entries);
	int entries = min(max_internal, entire_entries);

	for (i = 0; i < entries; i++) {
		addr = aeon_pull_extent_addr(sb, sih, i);
		if (!addr) {
			aeon_err(sb, "addr 0x%llx", addr);
			return -EINVAL;
		}
		ae = (struct aeon_extent *)addr;
		blocknr = le64_to_cpu(ae->ex_block);
		length = le16_to_cpu(ae->ex_length);
		if (!blocknr) {
			AEON_ERR(__LINE__); /*TODO: study if it is needed */
			continue;
		}

		err = aeon_insert_blocks_into_free_list(sb, blocknr, length, 0);
		if (err) {
			aeon_err(sb, "%s: failed\n", __func__);
			return -EINVAL;
		}
	}

	return 0;
}

int
aeon_delete_extenttree(struct super_block *sb,
		       struct aeon_inode_info_header *sih)
{
	struct aeon_extent *ae;
	Iterator *itr;
	unsigned long blocknr;
	int length;
	int err;

	read_lock(&sih->i_meta_lock);

	err = free_internal_extents(sb, sih);
	if (err) {
		aeon_err(sb, "%s: failed-1\n", __func__);
		return -EINVAL;
	}

	itr = init_delete(sb, sih);
	while (itr->hasNext(itr)) {
		ae = itr->getCurrExtent(itr);

		blocknr = le64_to_cpu(ae->ex_block);
		length = le16_to_cpu(ae->ex_length);
		if (!blocknr) {
			AEON_ERR(__LINE__); /*TODO: study if it is needed */
			goto next;
		}

		err = aeon_insert_blocks_into_free_list(sb, blocknr, length, 0);
		if (err) {
			aeon_err(sb, "%s: failed-2\n", __func__);
			return -EINVAL;
		}
next:
		itr = itr->next(itr);
	}
	final_delete(itr);

	read_unlock(&sih->i_meta_lock);

	return 0;
}

/*TODO: Change it by iterator later */
static struct aeon_extent
*pull_internal_extent(struct super_block *sb,
		      struct aeon_inode_info_header *sih, int index)
{
	return (struct aeon_extent *)aeon_pull_extent_addr(sb, sih, index);
}

static struct aeon_extent
*pull_external_extent(struct super_block *sb,
		      struct aeon_inode_info_header *sih, int index)
{
	return aeon_rb_search_extent(sb, sih, index);
}

static int
aeon_remove_extenttree(struct super_block *sb,
		       struct aeon_inode_info_header *sih, unsigned long offset)
{
	struct aeon_extent *ae;
	struct aeon_range_node *ret_node = NULL;
	bool found = false;

	found = aeon_find_range_node(&sih->rb_tree, offset,
				     NODE_EXTENT, &ret_node);
	if (!found) {
		aeon_err(sb, "%s target not found: %lu\n", __func__, offset);
		return -EINVAL;
	}

	ae = ret_node->extent;
	rb_erase(&ret_node->node, &sih->rb_tree);
	aeon_free_extent_node(ret_node);

	return 0;
}

int
aeon_cutoff_extenttree(struct super_block *sb,
		       struct aeon_inode_info_header *sih,
		       struct aeon_inode *pi, int remaining, int index)
{
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	struct aeon_extent *ae;
	unsigned long blocknr;
	unsigned long offset;
	int length;
	int err;

	while (remaining > 0) {
		if (index < PI_MAX_INTERNAL_EXTENT)
			ae = pull_internal_extent(sb, sih, index);
		else
			ae = pull_external_extent(sb, sih, index);

		blocknr = le64_to_cpu(ae->ex_block);
		length = le16_to_cpu(ae->ex_length);
		offset = le32_to_cpu(ae->ex_offset);

		err = aeon_insert_blocks_into_free_list(sb, blocknr, length, 0);
		if (err) {
			aeon_err(sb, "%s: %d - failed\n", __LINE__, __func__);
			return -EINVAL;
		}

		err = aeon_remove_extenttree(sb, sih, offset);
		if (err) {
			aeon_err(sb, "%s: %d - failed\n", __LINE__, __func__);
			return -EINVAL;
		}

		aeh->eh_entries--;
		aeh->eh_blocks -= cpu_to_le32(length);
		ae->ex_block = 0;
		ae->ex_length = 0;
		ae->ex_offset = 0;

		index++;
		remaining--;
	}

	return 0;
}

int
aeon_rebuild_rb_extenttree(struct super_block *sb,
			   struct inode *inode, int entries)
{
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	Iterator *itr;
	int err;

	err = aeon_build_new_rb_extent_tree(sb, sih);
	if (err) {
		aeon_err(sb, "%s - rebuild rb_extent_tree\n", __func__);
		return err;
	}

	/* Insert remaining extetns into the tree */
	read_lock(&sih->i_meta_lock);
	itr = init_lookup(sb, sih);
	while (itr->hasNext(itr)) {
		struct aeon_range_node *node;
		struct aeon_extent *ae;

		ae = itr->getCurrExtent(itr);

		node = aeon_alloc_extent_node(sb);
		if (!node) {
			read_unlock(&sih->i_meta_lock);
			return -ENOMEM;
		}
		node->offset = le32_to_cpu(ae->ex_offset);
		node->length = le16_to_cpu(ae->ex_length);
		node->extent = ae;

		err = do_aeon_insert_extenttree(&sih->rb_tree, node);
		if (err) {
			aeon_err(sb, "%s - insert_extenttree\n", __func__);
			aeon_free_extent_node(node);
			read_unlock(&sih->i_meta_lock);
			return err;
		}

		itr = itr->next(itr);
	}
	final_lookup(itr);
	read_unlock(&sih->i_meta_lock);

	return 0;
}
