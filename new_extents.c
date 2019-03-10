/*
 * New Extents support for AEON
 * ON THE WAY
 *
 * Design Overview
 *
 * |--inode--|
 * | header  | to manage all extents
 * | extents | first few extents embedded in the inode
 * |---------|
 *
 * Address           Address           Address           Address
 * #1                #100              #500              #800
 *
 * |----------|      |----------|      |----------|      |----------|
 * |--header--|  |-->|--header--|  |-->|--header--|  |-->|          |
 * | height 2 |  |   | height 1 |  |   | height 0 |  |   |          |
 * |----------|  |   |----------|  |   |----------|  |   |          |
 * |---idx1---|  |   |---idx1---|  |   |--extent--|  |   |          |
 * | offset 0 |--|   | offset 0 |--|   | offset 0 |--|   |----------|
 * | addr 100 |      | addr 500 |      | len    2 |
 * |----------|      |----------|      | addr 800 |      Address
 * |   ...    |      |---idx2---|      |----------|      #900
 * |          |      | offset 9 |      |--extent--|
 * |          |      | addr 600 |      | offset 2 |--|   |----------|
 * |----------|      |----------|      | len    1 |  |-->|          |
 *                   |   ...    |      | addr 900 |      |          |
 *                   |          |      |----------|      |----------|
 *                   |----------|      |   ...    |
 *                                     |----------|
 *
 * Enable to handle about 16TiB regions by above management.
 * DON'T USE GLOBAL RED-BLACK Tree to mange a file,
 * use the tree to mange each extent block...
 * I'm wondering which are fast, linear or binary to search just 128 elements,
 * though both of them will be implemented for study.
 * - First some extents are embedded the inode.
 * - Max height 3
 * - 254 idxs per 4k block
 * - 254 extents per 4k block
 */
#include <linux/fs.h>

#include "aeon.h"
#include "aeon_super.h"
#include "aeon_extents.h"
#include "aeon_balloc.h"

u64
_aeon_pull_extent_addr(struct super_block *sb,
		       struct aeon_inode_info_header *sih, int index)
{
//	struct aeon_inode *pi = aeon_get_inode(sb, sih);
//	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
//	u64 addr;
//
//	if (index < PI_MAX_INTERNAL_EXTENT) {
//		addr = (u64)&pi->ae[index];
//		return addr;
//	}
//
	return 0;
}

/*
 * Maybe new design is realized by this point?
 * (not considering error case, though)
 */
static struct aeon_extent
*do_aeon_get_extent2(struct super_block *sb, struct aeon_extent_header *in_ino)
{
	struct aeon_extent_middle_header *aemh;
	struct aeon_extent *ae;
	u64 addr = 0;
	int err;
	int entries;

	if (!le16_to_cpu(in_ino->eh_depth)) {
		err = aeon_get_new_extents_block_addr(sb, &addr);
		if (err) {
			AEON_ERR(err);
			return ERR_PTR(err);
		}

		in_ino->eh_depth++;
		in_ino->eh_up = le64_to_cpu(addr);

		aemh = (struct aeon_extent_middle_header *)addr;
		aeon_init_extent_middle_header(aemh);
	}

	addr = le64_to_cpu(in_ino->eh_up);
	aemh = (struct aeon_extent_middle_header *)addr;

	entries = le16_to_cpu(aemh->eh_entries);
	ae = (struct aeon_extent *)(addr + sizeof(aemh) + sizeof(ae) * entries);

	return ae;
}

static struct aeon_extent
*do_aeon_get_extent(struct super_block *sb, struct aeon_inode_info_header *sih)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	int entries;

	/*
	 * First PI_MAX_INTERNAL_EXTENT is embedded in the inode.
	 */
	entries = le16_to_cpu(aeh->eh_entries);
	if (entries < PI_MAX_INTERNAL_EXTENT) {
		aeh->eh_entries++;
		return &pi->ae[entries];
	}

	/*
	 * the other extents are in new regions.
	 */
	return do_aeon_get_extent2(sb, aeh);
}

static struct aeon_extent
*aeon_get_new_extent(struct super_block *sb, struct aeon_inode_info_header *sih)
{
	struct aeon_extent *ret;

	//TODO: the way of lock
	write_lock(&sih->i_meta_lock);
	ret = do_aeon_get_extent(sb, sih);
	write_unlock(&sih->i_meta_lock);

	return ret;
}

struct aeon_extent
*__aeon_search_extent(struct super_block *sb,
		    struct aeon_inode_info_header *sih, unsigned long offset)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	struct aeon_extent *ret;
	int entries = le32_to_cpu(aeh->eh_entries);

	if (!entries)
		return NULL;

	return NULL;
}

int
aeon_update_extent(struct super_block *sb, struct inode *inode,
		   unsigned long blocknr, unsigned long offset, int num_blocks)
{
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	struct aeon_extent *ae;

	ae = aeon_get_new_extent(sb, sih);
	if (IS_ERR(ae)) {
		aeon_err(sb, "can't expand file more");
	}

	write_lock(&sih->i_meta_lock);

	ae->ex_index = aeh->eh_entries;
	ae->ex_length = cpu_to_le16(num_blocks);
	ae->ex_block = cpu_to_le64(blocknr);
	ae->ex_offset = cpu_to_le32(offset);
	aeh->eh_blocks += cpu_to_le16(num_blocks);
	aeh->eh_prev_extent = cpu_to_le64(ae);

	pi->i_blocks = aeh->eh_blocks * 8;
	inode->i_blocks = le32_to_cpu(pi->i_blocks);

	// TODO insert extenttree on pmem

	write_unlock(&sih->i_meta_lock);

	//TODO?
	return 0;
}
