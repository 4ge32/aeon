#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/iomap.h>
#include <linux/uio.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>

#include "aeon.h"
#include "aeon_balloc.h"
#include "aeon_extents.h"
#include "aeon_compression.h"


static loff_t aeon_llseek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	loff_t maxbytes = inode->i_sb->s_maxbytes;

	if (origin != SEEK_DATA && origin != SEEK_HOLE)
		return generic_file_llseek(file, offset, origin);


	switch (origin) {
	case SEEK_DATA:
		aeon_dbg("DATA\n");
		inode_lock_shared(inode);
		offset = iomap_seek_data(inode, offset, &aeon_iomap_ops);
		inode_unlock_shared(inode);
		break;
	case SEEK_HOLE:
		aeon_dbg("SEEK\n");
		inode_lock_shared(inode);
		offset = iomap_seek_hole(inode, offset, &aeon_iomap_ops);
		inode_unlock_shared(inode);
		break;
	}

	if (offset < 0)
		return offset;

	return vfs_setpos(file, offset, maxbytes);
}

//static ssize_t do_dax_mapping_read(struct inode *inode, char __user *buf,
//				   size_t len, loff_t *ppos)
//{
//	struct super_block *sb = inode->i_sb;
//	struct aeon_inode_info *si = AEON_I(inode);
//	struct aeon_inode_info_header *sih = &si->header;
//	struct aeon_extent *ae;
//	pgoff_t index;
//	pgoff_t end_index;
//	unsigned long offset;
//	loff_t isize;
//	loff_t pos;
//	size_t copied = 0;
//	size_t err = 0;
//
//	pos = *ppos;
//	index = pos >> PAGE_SHIFT;
//	offset = pos & ~PAGE_MASK;
//
//	if (!access_ok(VERIFY_WRITE, buf, len)) {
//		err = -EFAULT;
//		goto out;
//	}
//
//	isize = i_size_read(inode);
//	if (!isize)
//		goto out;
//
//	if (len > isize - pos)
//		len = isize - pos;
//
//	if (len <= 0)
//		goto out;
//
//	aeon_dbgv("-----------------IN------------------\n");
//	end_index = (isize - 1) >> PAGE_SHIFT;
//	do {
//		unsigned long nr = 0;
//		unsigned long left;
//		unsigned long nvmm;
//		unsigned long ex_offset;
//		void *dax_mem = NULL;
//		int pages;
//		ssize_t copying;
//
//		if (index >= end_index) {
//			if (index > end_index)
//				goto out;
//			nr = ((isize - 1) & ~PAGE_MASK) + 1;
//			if (nr <= offset)
//				goto out;
//
//		}
//
//		aeon_dbgv("START----------\n");
//		aeon_dbgv("isize     %lld\n", isize);
//		aeon_dbgv("len       %lu\n", len);
//		aeon_dbgv("nr        %lu\n", nr);
//		aeon_dbgv("offset    %lu\n", offset);
//		aeon_dbgv("index     %lu\n", index);
//		aeon_dbgv("end index %lu\n", end_index);
//
//		ae = aeon_search_extent(sb, sih, index);
//		if (!ae) {
//			aeon_err(sb, "can't find target data\n");
//			return 0;
//		}
//
//		ex_offset = le16_to_cpu(ae->ex_offset);
//		aeon_dbg("extent    0x%llx\n", (u64)ae);
//		aeon_dbg("extent of %ld\n", ex_offset);
//
//		nvmm = le64_to_cpu(ae->ex_block);
//		pages = le16_to_cpu(ae->ex_length) - (index - ex_offset);
//		nvmm += (index - ex_offset);
//		dax_mem = aeon_get_block(sb, nvmm << AEON_SHIFT);
//
//		aeon_dbgv("block    %llu\n", le64_to_cpu(ae->ex_block));
//		aeon_dbgv("nvmm     0x%lx\n", nvmm);
//		aeon_dbgv("pages    %d\n", pages);
//
//		copying = pages << PAGE_SHIFT;
//		if (len < copying + copied)
//			nr = len - copied;
//		else
//			nr = copying;
//
//		aeon_dbgv("READ-----------\n");
//		aeon_dbgv("len      %lu\n", len);
//		aeon_dbgv("copied   %lu\n", copied);
//		aeon_dbgv("offset   %ld\n", offset);
//		aeon_dbgv("copying  %ld\n", copying);
//		aeon_dbgv("nr       %ld\n", nr);
//		aeon_dbgv("nr       %ld\n", nr >> PAGE_SHIFT);
//		aeon_dbgv("dax_mem  0x%lx\n", (unsigned long)dax_mem);
//
//		left = copy_to_user(buf + copied, dax_mem + offset, nr);
//		copied += (nr - left);
//		offset += (nr - left);
//		index += (offset >> PAGE_SHIFT);
//		aeon_dbgv("DONE-----------\n");
//		aeon_dbgv("len      %lu\n", len);
//		aeon_dbgv("left     %lu\n", left);
//		aeon_dbgv("copied   %lu\n", copied);
//		aeon_dbgv("offset   %ld\n", offset);
//		offset &= ~PAGE_MASK;
//		aeon_dbgv("offset   %ld\n", offset);
//		aeon_dbgv("index    %lu\n", index);
//		aeon_dbgv("REMAIN   %lu\n", len - copied);
//		aeon_dbgv("dax_mem  0x%lx\n", (unsigned long)dax_mem);
//	} while (copied < len);
//
//out:
//	*ppos = pos + copied;
//
//	aeon_dbg("copied return     %lu\n", copied);
//	return copied ? copied : err;
//}
//
//static ssize_t aeon_read(struct file *filp, char __user *buf,
//			 size_t len, loff_t *ppos)
//{
//	struct inode *inode = filp->f_mapping->host;
//	ssize_t ret;
//
//	inode_lock_shared(inode);
//
//	ret = do_dax_mapping_read(inode, buf, len, ppos);
//
//	if (filp)
//		file_accessed(filp);
//
//	inode_unlock_shared(inode);
//
//	return ret;
//}
//
//static ssize_t aeon_write(struct file *filp, const char __user *buf,
//			  size_t len, loff_t *ppos)
//{
//	struct address_space *mapping = filp->f_mapping;
//	struct inode *inode = mapping->host;
//	struct aeon_inode_info *si = AEON_I(inode);
//	struct aeon_inode_info_header *sih = &si->header;
//	struct super_block *sb = inode->i_sb;
//	struct aeon_inode *pi = aeon_get_inode(sb, sih);
//	unsigned long total_blocks;
//	unsigned long blocknr;
//	unsigned long num_blocks;
//	unsigned long new_blocks = 0;
//	unsigned long start_blk;
//	unsigned long new_d_blocknr = 0;
//	unsigned int data_bits;
//	void *kmem;
//	u64 blk_off;
//	u64 file_size;
//	u32 time;
//	loff_t pos;
//	ssize_t ret = -1;
//	ssize_t written = 0;
//	ssize_t offset;
//	size_t count;
//	size_t bytes;
//	size_t copied;
//	long status = 0;
//	int allocated;
//
//	aeon_dbg("WRITE-----------------------------\n");
//
//	if (len == 0)
//		return 0;
//
//	if (!access_ok(VERIFY_READ, buf, len)) {
//		ret = -EFAULT;
//		goto out;
//	}
//
//	pos = *ppos;
//
//	if (filp->f_flags & O_APPEND)
//		pos = i_size_read(inode);
//
//	count = len;
//	offset = pos & (sb->s_blocksize - 1);
//	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
//	total_blocks = num_blocks;
//
//	aeon_dbgv("len          %lu\n", len);
//	aeon_dbgv("offset       %lu\n", offset);
//	aeon_dbgv("num_blocks   %lu\n", num_blocks);
//	aeon_dbgv("total_blocks %lu\n", total_blocks);
//
//	ret = file_remove_privs(filp);
//	if (ret)
//		goto out;
//
//	inode->i_ctime = inode->i_mtime = current_time(inode);
//	time = current_time(inode).tv_sec;
//
//	while (num_blocks > 0) {
//		struct aeon_extent_header *aeh;
//		struct aeon_extent *ae;
//		int err;
//
//		start_blk = pos >> sb->s_blocksize_bits;
//
//		aeon_dbgv("offset       %lu\n", offset);
//		aeon_dbgv("pos          %lld\n", pos);
//		aeon_dbgv("start_blk    %lu\n", start_blk);
//
//		ae = aeon_search_extent(sb, sih, );
//		if (ae) {
//			aeon_dbgv("FOUND\n");
//			blocknr = le64_to_cpu(ae->ex_block);
//			allocated = le16_to_cpu(ae->ex_length);
//		} else {
//			aeon_dbgv("ALLOCATED\n");
//			aeh = aeon_get_extent_header(pi);
//			if (!pi->i_exblocks) {
//				pi->i_new = 0;
//				pi->i_exblocks++;
//				aeon_init_extent_header(aeh);
//			}
//			allocated = aeon_new_data_blocks(sb, sih, &new_d_blocknr,
//							 start_blk, num_blocks, ANY_CPU);
//			if (allocated <= 0) {
//				aeon_err(sb, "%s\n", __func__);
//				ret = allocated;
//				goto out;
//			}
//
//			err = aeon_update_extent(sb, inode, new_d_blocknr,
//						 offset, allocated);
//			if (err) {
//				aeon_err(sb, "failed to update extent\n");
//				goto out;
//			}
//
//			blocknr = new_d_blocknr;
//
//			clean_bdev_aliases(sb->s_bdev, blocknr, allocated);
//			err = sb_issue_zeroout(sb, blocknr, allocated, GFP_NOFS);
//			if (err) {
//				aeon_err(sb, "%s: sb_issue_zero_out\n", __func__);
//				goto out;
//			}
//
//		}
//
//		aeon_dbgv("allocated    %d\n", allocated);
//		aeon_dbgv("blocknr      %lu\n", blocknr);
//
//		bytes = (sb->s_blocksize) * allocated - offset;
//		if (bytes > count)
//			bytes = count;
//
//		blk_off = blocknr << AEON_SHIFT;
//		aeon_dbgv("bytes        %lu\n", bytes);
//
//		kmem = aeon_get_block(sb, blk_off);
//
//		aeon_dbgv("kmem         0x%lx\n", (unsigned long)kmem);
//		copied = bytes - memcpy_to_pmem_nocache(kmem + offset,
//							buf, bytes);
//		if (pos + copied > inode->i_size)
//			file_size = cpu_to_le64(pos + copied);
//		else
//			file_size = cpu_to_le64(inode->i_size);
//
//		aeon_dbgv("copied       %lu\n", copied);
//		if (copied > 0) {
//			status = copied;
//			written += copied;
//			pos += copied;
//			buf += copied;
//			count -= copied;
//			num_blocks -= allocated;
//		}
//
//		if (unlikely(copied != bytes)) {
//			aeon_err(sb, "%s ERROR!: %p, bytes %lu, copied %lu\n",
//				__func__, kmem, bytes, copied);
//			if (status >= 0)
//				status = -EFAULT;
//		}
//
//		if (status < 0)
//			break;
//
//	}
//
//	data_bits = 0x1000;
//	inode->i_blocks += (new_blocks << (data_bits - sb->s_blocksize_bits));
//
//	ret = written;
//
//	*ppos = pos;
//	if (pos > inode->i_size) {
//		i_size_write(inode, pos);
//		inode->i_size = pos;
//	}
//out:
//	if (ret < 0) {
//		aeon_err(sb, "%s error\n", __func__);
//		return ret;
//	}
//
//	return ret;
//}

static inline void wrap_file_accessed(struct file *fp)
{
	if (!(fp->f_flags & O_NOATIME)) {
		struct aeon_inode *pi;
		struct inode *inode = fp->f_path.dentry->d_inode;

		pi = aeon_get_inode(inode->i_sb, &AEON_I(inode)->header);
		touch_atime(&fp->f_path);
		pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	}
}

static ssize_t aeon_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	ssize_t ret;
#ifdef CONFIG_AEON_FS_COMPRESSION
	struct aeon_inode *pi;
	pi = aeon_get_inode(inode->i_sb, &AEON_I(inode)->header);
#endif

	if(!iov_iter_count(to))
		return 0;

	inode_lock_shared(inode);
	ret = dax_iomap_rw(iocb, to, &aeon_iomap_ops);
	inode_unlock_shared(inode);

#ifdef CONFIG_AEON_FS_COMPRESSION
	/* TODO
	 * Handle the case that ret is not equal to from->count
	 */
	if (!ret)
		goto out;
	if (pi->compressed)
		ret = aeon_decompress_data_iter(ret, to);
out:
#endif

	wrap_file_accessed(iocb->ki_filp);

	return ret;
}

static inline void wrap_i_size_write(struct inode *inode, struct kiocb *iocb)
{
	struct aeon_inode *pi;

	pi = aeon_get_inode(inode->i_sb, &AEON_I(inode)->header);

	i_size_write(inode, iocb->ki_pos);
	pi->i_size = cpu_to_le64(inode->i_size);
}

static ssize_t aeon_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

#ifdef CONFIG_AEON_FS_COMPRESSION
	size_t tmp = from->count;
#endif

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

#ifdef CONFIG_AEON_FS_COMPRESSION
	/* TODO
	 * Handle the case that ret is not equal to from->count
	 */
	ret = aeon_compress_data_iter(inode, from);
	if (ret)
		goto out_unlock;
#endif

	ret = dax_iomap_rw(iocb, from, &aeon_iomap_ops);
	if (ret > 0 && iocb->ki_pos > i_size_read(inode))
		wrap_i_size_write(inode, iocb);

out_unlock:
	inode_unlock(inode);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);

#ifdef CONFIG_AEON_FS_COMPRESSION
	aeon_dbg("GGG %llu %lu %llu\n", iocb->ki_pos, from->count, i_size_read(inode));
	aeon_dbg("ret %lu\n", ret);
	ret = tmp;
#endif
	return ret;
}

static int aeon_dax_huge_fault(struct vm_fault *vmf,
			       enum page_entry_size pe_size)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	bool write;
	int res = 0;

	write = (vmf->flags & FAULT_FLAG_WRITE);

	if (write) {
		sb_start_pagefault(sb);
		file_update_time(vmf->vma->vm_file);
	}
	down_read(&sih->dax_sem);

	res = dax_iomap_fault(vmf, pe_size, NULL, NULL, &aeon_iomap_ops);

	up_read(&sih->dax_sem);

	if (write)
		sb_end_pagefault(sb);

	return res;
}

static int aeon_dax_fault(struct vm_fault *vmf)
{
	return aeon_dax_huge_fault(vmf, PE_SIZE_PTE);
}

static const struct vm_operations_struct aeon_dax_vm_ops = {
	.fault		= aeon_dax_fault,
	//.huge_fault	= aeon_dax_huge_fault,
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

static int aeon_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	return generic_file_fsync(file, start, end, datasync);
}

static int aeon_open(struct inode *inode, struct file *file)
{
	return generic_file_open(inode, file);
}

const struct file_operations aeon_dax_file_operations = {
	.llseek		= aeon_llseek,
	//.read		= aeon_read,
	//.write          = aeon_write,
	.read_iter	= aeon_file_read_iter,
	.write_iter	= aeon_file_write_iter,
	.mmap           = aeon_mmap,
	.fsync		= aeon_fsync,
	.open		= aeon_open,
	.unlocked_ioctl = aeon_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= aeon_compat_ioctl,
#endif
};

const struct inode_operations aeon_file_inode_operations = {
	.setattr	= aeon_setattr,
	.update_time	= aeon_update_time,
};

static int aeon_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
			    unsigned flags, struct iomap *iomap)
{
	struct aeon_sb_info *sbi = AEON_SB(inode->i_sb);
	unsigned int blkbits = inode->i_blkbits;
	unsigned long first_block = offset >> blkbits;
	unsigned long max_blocks = (length + (1 << blkbits) - 1) >> blkbits;
	bool new = false, boundary = false;
	u32 bno = 0;
	int ret;

	ret = aeon_dax_get_blocks(inode, first_block, max_blocks,
				  &bno, &new, &boundary, flags & IOMAP_WRITE);
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

	return 0;
}

static void aeon_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		aeon_truncate_blocks(inode, inode->i_size);
	}
}

static int aeon_iomap_end(struct inode *inode, loff_t offset, loff_t length,
			  ssize_t written, unsigned flags, struct iomap *iomap)
{
	if (iomap->type == IOMAP_MAPPED &&
	    written < length && (flags & IOMAP_WRITE)) {
		aeon_write_failed(inode->i_mapping, offset + length);
	}
	return 0;
}

const struct iomap_ops aeon_iomap_ops = {
	.iomap_begin = aeon_iomap_begin,
	.iomap_end   = aeon_iomap_end,
};
