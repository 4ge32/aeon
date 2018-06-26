#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/iomap.h>
#include <linux/uio.h>

#include "aeon.h"
#include "super.h"
#include "balloc.h"
#include "inode.h"
#include "mprotect.h"

static ssize_t aeon_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	ssize_t ret;

	aeon_dbg("%s: START1\n", __func__);
	aeon_dbg("%s: to->i_count - %lu\n", __func__, to->count);

	if(!iov_iter_count(to))
		return 0;

	aeon_dbg("%s: START2\n", __func__);
	inode_lock_shared(inode);
	ret = dax_iomap_rw(iocb, to, &aeon_iomap_ops);
	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);
	aeon_dbg("%s: FINISH\n", __func__);

	return ret;
}

static ssize_t aeon_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	aeon_dbg("%s: START\n", __func__);

	aeon_dbg("%s: to->i_count - %lu", __func__, from->count);

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out_unlock;
	ret = file_remove_privs(file);
	if (ret)
		goto out_unlock;
	ret = file_update_time(file);
	if (ret)
		goto out_unlock;

	ret = dax_iomap_rw(iocb, from, &aeon_iomap_ops);
	if (ret > 0 && iocb->ki_pos > i_size_read(inode)) {
		i_size_write(inode, iocb->ki_pos);
		mark_inode_dirty(inode);
	}

out_unlock:
	inode_unlock(inode);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	aeon_dbg("%s: FINISH\n", __func__);
	return ret;
}

const struct file_operations aeon_dax_file_operations = {
	.read_iter  = aeon_file_read_iter,
	.write_iter = aeon_file_write_iter,
};

/*
 * return > 0, # of blocks mapped or allocated.
 * return = 0, if plain lookup failed.
 * return < 0, error case.
 */
static int aeon_dax_get_blocks(struct inode *inode, sector_t iblock,
	unsigned long max_blocks, u32 *bno, bool *new, bool *boundary, int create)
{
	*bno = 5;
	return 1;
}

static int aeon_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
		            unsigned flags, struct iomap *iomap)
{
	struct aeon_sb_info *sbi = AEON_SB(inode->i_sb);
	unsigned int blkbits = inode->i_blkbits;
	unsigned long first_block = offset >> blkbits;
	unsigned long max_blocks = (length + (1 << blkbits) - 1) >> blkbits;
	unsigned long head_addr = (unsigned long)sbi->virt_addr;
	bool new = false, boundary = false;
	u32 bno = 0;
	int ret;

	aeon_dbg("%s: START\n", __func__);

	ret = aeon_dax_get_blocks(inode, first_block, max_blocks, &bno, &new,
			          &boundary, flags & IOMAP_WRITE);

	if (ret < 0)
		return ret;

	iomap->flags = 0;
	iomap->bdev = inode->i_sb->s_bdev;
	iomap->dax_dev = sbi->s_dax_dev;
	iomap->offset = (u64)first_block << blkbits;

	if (ret == 0) {
		iomap->type = IOMAP_HOLE;
		iomap->addr = IOMAP_NULL_ADDR;
		iomap->length = 1 << blkbits;
	} else {
		iomap->type = IOMAP_MAPPED;
		iomap->addr = (u64)bno << (blkbits - 9);
		iomap->length = (u64)ret << blkbits;
		iomap->flags |= IOMAP_F_MERGED;
	}

	if (new)
		iomap->flags |= IOMAP_F_NEW;

	aeon_dbg("%s: FINISH, head addr - 0x%lx first_block - 0x%lx ret - 0x%x addr - 0x%llx length - 0x%llx\n", __func__, head_addr, first_block, ret, iomap->addr, iomap->length);
	aeon_dbg("0x%llx\n", (u64)bno);
	return 0;
}

static int aeon_iomap_end(struct inode *inode, loff_t offset, loff_t length,
			  ssize_t written, unsigned flags, struct iomap *iomap)
{
	return 0;
}

const struct iomap_ops aeon_iomap_ops = {
	.iomap_begin = aeon_iomap_begin,
	.iomap_end   = aeon_iomap_end,
};
