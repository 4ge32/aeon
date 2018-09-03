#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/iomap.h>
#include <linux/uio.h>

#include "aeon.h"


static loff_t aeon_llseek(struct file *file, loff_t offset, int origin)
{
	//aeon_dbgv("%s\n", __func__);
	return generic_file_llseek(file, offset, origin);
}

static ssize_t aeon_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	ssize_t ret;

	if(!iov_iter_count(to))
		return 0;

	inode_lock_shared(inode);
	ret = dax_iomap_rw(iocb, to, &aeon_iomap_ops);
	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);

	return ret;
}

static ssize_t aeon_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

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
	/* TODO:
	 * Change writing size into vfs inode to inode on pm.
	 * In case of it, generic_write_sync() and mark_inode_dirty()
	 * could be removed.
	 */
	if (ret > 0 && iocb->ki_pos > i_size_read(inode)) {
		i_size_write(inode, iocb->ki_pos);
		mark_inode_dirty(inode);
	}

out_unlock:
	inode_unlock(inode);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}

static int aeon_dax_huge_fault(struct vm_fault *vmf, enum page_entry_size pe_size)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	bool write;
	pfn_t pfn;
	int res = 0;
	int err = 0;

	write = (vmf->flags & FAULT_FLAG_WRITE) &&
		(vmf->vma->vm_flags & VM_SHARED);

	if (write) {
		sb_start_pagefault(sb);
		file_update_time(vmf->vma->vm_file);
	}
	down_read(&sih->i_mmap_sem);

	res = dax_iomap_fault(vmf, pe_size, &pfn, &err, &aeon_iomap_ops);
	if (write) {
		if (res & VM_FAULT_NEEDDSYNC)
			res = dax_finish_sync_fault(vmf, pe_size, pfn);
		up_read(&sih->i_mmap_sem);
		sb_end_pagefault(sb);
	} else
		up_read(&sih->i_mmap_sem);

	return res;
}

static int aeon_dax_fault(struct vm_fault *vmf)
{
	return aeon_dax_huge_fault(vmf, PE_SIZE_PTE);
}

static const struct vm_operations_struct aeon_dax_vm_ops = {
	.fault		= aeon_dax_fault,
	.huge_fault	= aeon_dax_huge_fault,
	.page_mkwrite	= aeon_dax_fault,
	.pfn_mkwrite	= aeon_dax_fault,
};

static int aeon_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_ops = &aeon_dax_vm_ops;
	vma->vm_flags |= VM_MIXEDMAP;
	return 0;
}

/*
 * Not need fsync. At least in the future.
 */
static int aeon_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	return 0;
}

static int aeon_open(struct inode *inode, struct file *file)
{
	return generic_file_open(inode, file);
}

const struct file_operations aeon_dax_file_operations = {
	.llseek		= aeon_llseek,
	.read_iter	= aeon_file_read_iter,
	.write_iter 	= aeon_file_write_iter,
	.mmap           = aeon_mmap,
	.fsync      	= aeon_fsync,
	.open       	= aeon_open,
};

const struct inode_operations aeon_file_inode_operations = {
	.setattr  	= aeon_setattr,
};

static int aeon_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
		            unsigned flags, struct iomap *iomap)
{
	struct aeon_sb_info *sbi = AEON_SB(inode->i_sb);
	unsigned int blkbits = inode->i_blkbits;
	unsigned long first_block = offset >> blkbits;
	unsigned long max_blocks = (length + (1 << blkbits) - 1) >> blkbits;
	//unsigned long head_addr = (unsigned long)sbi->virt_addr;
	bool new = false, boundary = false;
	u32 bno = 0;
	int ret;

	ret = aeon_dax_get_blocks(inode, first_block, max_blocks, &bno, &new,
			          &boundary, flags & IOMAP_WRITE);

	if (ret < 0)
		return ret;

	iomap->flags = 0;
	iomap->bdev = inode->i_sb->s_bdev;
	iomap->offset = (u64)first_block << blkbits;
	iomap->dax_dev = sbi->s_dax_dev;

	if (ret == 0) {
		iomap->type = IOMAP_HOLE;
		iomap->addr = IOMAP_NULL_ADDR;
		iomap->length = 1 << blkbits;
	} else {
		iomap->type = IOMAP_MAPPED;
		iomap->addr = (u64)bno << blkbits;
		iomap->length = (u64)ret << blkbits;
		iomap->flags |= IOMAP_F_MERGED;
	}

	if (new)
		iomap->flags |= IOMAP_F_NEW;

	//aeon_dbgv("%s: FINISH, head addr - 0x%lx first_block - 0x%lx ret - 0x%x addr - 0x%llx length - 0x%llx\n", __func__, head_addr, first_block, ret, iomap->addr, iomap->length);
	//aeon_dbgv("0x%llx\n", (u64)bno);
	return 0;
}

static int aeon_iomap_end(struct inode *inode, loff_t offset, loff_t length,
			  ssize_t written, unsigned flags, struct iomap *iomap)
{
	if (iomap->type == IOMAP_MAPPED && written < length && (flags & IOMAP_WRITE))
		truncate_pagecache(inode, inode->i_size);
	return 0;
}

const struct iomap_ops aeon_iomap_ops = {
	.iomap_begin = aeon_iomap_begin,
	.iomap_end   = aeon_iomap_end,
};
