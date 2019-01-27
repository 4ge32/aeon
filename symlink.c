#include <linux/fs.h>
#include <linux/crc32.h>

#include "aeon.h"
#include "aeon_balloc.h"

int aeon_delete_symblock(struct super_block *sb,
			 struct aeon_inode_info_header *sih)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	unsigned long blocknr;
	int err;

	blocknr = le64_to_cpu(pi->sym_block);
	err = aeon_insert_blocks_into_free_list(sb, blocknr, 1, 0);
	if (err) {
		aeon_err(sb, "%s: free symlonk pmem resource\n", __func__);
		return err;
	}

	return 0;
}

int aeon_block_symlink(struct super_block *sb, struct aeon_inode *pi,
		       const char *symname, int len)
{
	unsigned long blocknr;
	u64 pi_addr = 0;
	u64 block;
	char *blockp;

	blocknr = aeon_get_new_symlink_block(sb, &pi_addr);
	if (blocknr == 0)
		return -ENOSPC;

	block = aeon_get_block_off(sb, blocknr, AEON_BLOCK_TYPE_4K);
	blockp = (char *)aeon_get_address(sb, block, 0);

	memcpy_to_pmem_nocache(blockp, symname, len);
	blockp[len] = '\0';

	pi->sym_block = cpu_to_le64(blocknr);
	pi->csum = cpu_to_le32(crc32_le(pi->csum,
					(unsigned char *)pi,
					AEON_INODE_SIZE));

	return 0;
}

static const char *aeon_get_link(struct dentry *dentry, struct inode *inode,
			         struct delayed_call *done)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	unsigned blocknr;
	u64 block;
	char *blockp;

	blocknr = le64_to_cpu(pi->sym_block);
	block = aeon_get_block_off(sb, blocknr, AEON_BLOCK_TYPE_4K);
	blockp = (char *)aeon_get_address(sb, block, 0);

	return blockp;
}

const struct inode_operations aeon_symlink_inode_operations = {
	.get_link	= aeon_get_link,
	.setattr        = aeon_setattr,
	.update_time	= aeon_update_time,
};
