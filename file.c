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
		aeon_dbgv("DATA\n");
		inode_lock_shared(inode);
		offset = iomap_seek_data(inode, offset, &aeon_iomap_ops);
		inode_unlock_shared(inode);
		break;
	case SEEK_HOLE:
		aeon_dbgv("SEEK\n");
		inode_lock_shared(inode);
		offset = iomap_seek_hole(inode, offset, &aeon_iomap_ops);
		inode_unlock_shared(inode);
		break;
	}

	if (offset < 0)
		return offset;

	return vfs_setpos(file, offset, maxbytes);
}

#ifdef CONFIG_AEON_FS_AEON_RW
static ssize_t do_dax_mapping_read(struct inode *inode, char __user *buf,
				   size_t len, loff_t *ppos)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
#ifdef CONFIG_AEON_FS_COMPRESSION
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
#endif
	struct aeon_extent *ae;
	unsigned long offset;
	pgoff_t index;
	pgoff_t end_index;
	loff_t isize;
	loff_t pos;
	size_t copied = 0;
	size_t err = 0;

	pos = *ppos;
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	aeon_dbgv("-----------------PREP-----------------\n");
	if (!access_ok(VERIFY_WRITE, buf, len)) {
		err = -EFAULT;
		goto out;
	}

#ifdef CONFIG_AEON_FS_COMPRESSION
	isize = le64_to_cpu(pi->i_original_size);
#else
	isize = i_size_read(inode);
#endif
	if (!isize)
		goto out;

	aeon_dbgv("%lu \n", len);
	aeon_dbgv("%lld \n", isize);
	aeon_dbgv("%lld \n", pos);

	if (len > isize - pos)
		len = isize - pos;
	if (len <= 0)
		goto out;

	aeon_dbgv("-----------------IN------------------\n");

	end_index = (isize - 1) >> PAGE_SHIFT;

	aeon_dbgv("star ind %lu\n", index);
	aeon_dbgv("endi ind %lu\n", end_index);
	aeon_dbgv("nr       %llu\n", ((isize-1) & ~PAGE_MASK) + 1);

	do {
		unsigned long nr = 0;
		unsigned long left;
		unsigned long blocknr;
		unsigned long ex_offset;
		void *nvmm = NULL;
		int pages;
		ssize_t copying;

		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset)
				goto out;

		}

		aeon_dbgv("START----------\n");
		aeon_dbgv("isize     %lld\n", isize);
		aeon_dbgv("len       %lu\n", len);
		aeon_dbgv("nr        %lu\n", nr);
		aeon_dbgv("offset    %lu\n", offset);
		aeon_dbgv("index     %lu\n", index);
		aeon_dbgv("end index %lu\n", end_index);

		ae = aeon_search_extent(sb, sih, index);
		if (!ae) {
			aeon_err(sb, "can't find target data\n");
			return 0;
		}
		ex_offset = le16_to_cpu(ae->ex_offset);

		aeon_dbgv("extent    0x%llx\n", (u64)ae);
		aeon_dbgv("extent of %ld\n", ex_offset);

		blocknr = le64_to_cpu(ae->ex_block);
		pages = le16_to_cpu(ae->ex_length) - (index - ex_offset);
		blocknr += (index - ex_offset);
		nvmm = aeon_get_address(sb, blocknr<<AEON_SHIFT, 0);

#ifdef CONFIG_AEON_FS_COMPRESSION
		nvmm = aeon_decompress(nvmm, ae, pi);
		if (IS_ERR(nvmm)) {
			aeon_err(sb, "can't decompress data\n");
			return 0;
		}
copy_more:
#endif
		aeon_dbgv("---COPY ZONE---\n");
		aeon_dbgv("block    %llu\n", le64_to_cpu(ae->ex_block));
		aeon_dbgv("blocknr  0x%lx\n", blocknr);
		aeon_dbgv("pages    %d\n", pages);

		copying = pages << PAGE_SHIFT;
		if (len < copying + copied)
			nr = len - copied;
		else
			nr = copying;

		aeon_dbgv("READ-----------\n");
		aeon_dbgv("len      %lu\n", len);
		aeon_dbgv("copied   %lu\n", copied);
		aeon_dbgv("offset   %ld\n", offset);
		aeon_dbgv("copying  %ld\n", copying);
		aeon_dbgv("nr       %ld\n", nr);
		aeon_dbgv("nr       %ld\n", nr >> PAGE_SHIFT);
		aeon_dbgv("nvmm     0x%lx\n", (unsigned long)nvmm);

		left = copy_to_user(buf + copied, nvmm + offset, nr);
		copied += (nr - left);
		offset += (nr - left);
		index += (offset >> AEON_SHIFT);

		aeon_dbgv("DONE-----------\n");
		aeon_dbgv("len      %lu\n", len);
		aeon_dbgv("left     %lu\n", left);
		aeon_dbgv("copied   %lu\n", copied);
		aeon_dbgv("offset   %ld\n", offset);

		offset &= ~PAGE_MASK;

		aeon_dbgv("offset   %ld\n", offset);
		aeon_dbgv("index    %lu\n", index);
		aeon_dbgv("REMAIN   %lu\n", len - copied);
		aeon_dbgv("nvmm     0x%lx\n", (unsigned long)nvmm);
#ifdef CONFIG_AEON_FS_COMPRESSION
		aeon_dbgv("original %d\n", le16_to_cpu(ae->ex_original_length));
		if (copied < len &&
		    copied < le16_to_cpu(pi->i_original_size)) {
			offset += copied;
			goto copy_more;
		}
#endif
	} while (copied < len);

out:
	*ppos = pos + copied;

	aeon_dbgv("copied return     %lu\n", copied);
	return copied ? copied : err;
}

static ssize_t aeon_read(struct file *filp, char __user *buf,
			 size_t len, loff_t *ppos)
{
	struct inode *inode = filp->f_mapping->host;
	ssize_t ret;

	inode_lock_shared(inode);

	ret = do_dax_mapping_read(inode, buf, len, ppos);

	if (filp)
		file_accessed(filp);

	inode_unlock_shared(inode);

	return ret;
}

static void aeon_init_file(struct aeon_inode *pi,
			   struct aeon_extent_header *aeh)
{
	if (!le16_to_cpu(pi->i_exblocks)) {
		pi->i_new = 0;
		pi->i_exblocks++;
		aeon_init_extent_header(aeh);
	}
}

static int do_dax_get_new_blocks(struct super_block *sb,
				 struct inode *inode,
				 struct aeon_inode_info_header *sih,
				 unsigned long iblock,
				 unsigned long num_blocks,
				 unsigned long *ret_blocknr)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh;
	unsigned long blocknr = 0;
	int allocated;
	int err;

	aeh = aeon_get_extent_header(pi);
	aeon_init_file(pi, aeh);

	allocated = aeon_new_data_blocks(sb, sih, &blocknr,
					 iblock, num_blocks, ANY_CPU);
	if (allocated <= 0) {
		aeon_err(sb, "%s\n", __func__);
		return -ENOSPC;
	}

	*ret_blocknr = blocknr;

	err = aeon_update_extent(sb, inode, blocknr, iblock, allocated);
	if (err) {
		aeon_err(sb, "failed to update extent\n");
		goto out;
	}

	clean_bdev_aliases(sb->s_bdev, blocknr, allocated);
	err = sb_issue_zeroout(sb, blocknr, allocated, GFP_NOFS);
	if (err) {
		aeon_err(sb, "%s: sb_issue_zero_out\n", __func__);
		goto out;
	}

	return allocated;
out:
	return err;
}

static ssize_t aeon_write(struct file *filp, const char __user *buf,
			  size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct aeon_inode_info *si = AEON_I(inode);
	struct aeon_inode_info_header *sih = &si->header;
	struct aeon_inode *pi = aeon_get_inode(inode->i_sb, sih);
	struct aeon_extent_header *aeh = aeon_get_extent_header(pi);
	struct super_block *sb = inode->i_sb;
	unsigned long total_blocks;
	unsigned long num_blocks;
	unsigned long new_blocks = 0;
	unsigned long iblock;
	unsigned int data_bits;
	void *kmem;
	u64 blk_off;
	u64 file_size;
	u32 time;
	loff_t pos;
	ssize_t ret = -1;
	ssize_t written = 0;
	ssize_t offset;
	size_t count;
	size_t bytes;
	size_t copied = 0;
	long status = 0;
	int allocated;

	aeon_dbgv("WRITE-----------------------------\n");

	if (len == 0)
		return 0;

	if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out;
	}

	pos = *ppos;

	if (filp->f_flags & O_APPEND)
		pos = i_size_read(inode);

	count = len;
	iblock  = pos >> AEON_SHIFT;
	offset = (pos & (sb->s_blocksize - 1)) + (iblock<<AEON_SHIFT);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;

	aeon_dbgv("len          %lu\n", len);
	aeon_dbgv("pos    	%llu\n", pos);
	aeon_dbgv("offset       %lu\n", offset);
	aeon_dbgv("num_blocks   %lu\n", num_blocks);
	aeon_dbgv("total_blocks %lu\n", total_blocks);

	ret = file_remove_privs(filp);
	if (ret)
		goto out;

	inode->i_ctime = inode->i_mtime = current_time(inode);
	time = current_time(inode).tv_sec;

#ifdef CONFIG_AEON_FS_COMPRESSION
	{
		void *compressed_data;
		unsigned long outlen = 0;

		compressed_data = aeon_compress(buf, len, &outlen);
		if (IS_ERR(compressed_data)) {
			aeon_err(sb, "failed to compress data\n");
			goto out;
		}
		num_blocks = ((1<<AEON_SHIFT) + outlen - 1)>>AEON_SHIFT;
		buf = compressed_data;
		aeon_dbg("!len %lu %lu %lu\n", len, outlen, num_blocks);
	}
#endif

	while (count > 0) {
		struct aeon_extent *ae;
		unsigned long blocknr = 0;

		//num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
		num_blocks = ((count - 1) >> sb->s_blocksize_bits) + 1;

		aeon_dbgv("iblock       %lu\n", iblock);
		aeon_dbgv("pos          %lld\n", pos);
		aeon_dbgv("iblock       %lu\n", iblock);
		aeon_dbgv("count        %lu\n", count);
		aeon_dbgv("num_blocks   %lu\n", num_blocks);

		ae = aeon_search_extent(sb, sih, iblock);
		if (!ae) {
			aeon_dbgv("ALLOCATED\n");
			allocated = do_dax_get_new_blocks(sb, inode, sih, iblock,
							  num_blocks, &blocknr);
			if (allocated <= 0) {
				AEON_ERR(-ENOSPC);
				goto out;
			}
			offset = 0;
#ifdef CONFIG_AEON_FS_COMPRESSION
			{
			struct aeon_inode *pi = aeon_get_inode(sb, sih);
			pi->i_original_size = cpu_to_le64(len);
			ae = aeon_get_prev_extent(aeon_get_extent_header(pi));
			ae->ex_original_length = cpu_to_le16(((1<<AEON_SHIFT) +
						      len - 1) >> AEON_SHIFT);
			}
#endif
		} else {
			aeon_dbgv("NOT ALLOCATE\n");
			blocknr = le64_to_cpu(ae->ex_block);
			allocated = le32_to_cpu(aeh->eh_blocks);
			count = (sb->s_blocksize) * allocated - pos;
		}

		aeon_dbgv("---allocated %d\n", allocated);
		aeon_dbgv("blocknr      %lu\n", blocknr);
		aeon_dbgv("pos          %llu\n", pos);
		aeon_dbgv("offset       %lu\n", offset);
		aeon_dbgv("count        %lu\n", count);

		bytes = (sb->s_blocksize) * allocated - offset;
		if (bytes > count)
			bytes = count;

		blk_off = blocknr<<AEON_SHIFT;
		kmem = aeon_get_address(sb, blk_off, 0);

		aeon_dbgv("---kmem      0x%lx\n", (unsigned long)kmem);
		aeon_dbgv("offset       %lu\n", offset);
		aeon_dbgv("bytes        %lu\n", bytes);
		aeon_dbgv("copied       %lu\n", copied);
		copied = bytes -
			memcpy_to_pmem_nocache(kmem + offset, buf, bytes);
		if (pos + copied > inode->i_size)
			file_size = cpu_to_le64(pos + copied);
		else
			file_size = cpu_to_le64(inode->i_size);

		aeon_dbgv("copied       %lu\n", copied);
		aeon_dbgv("total        %llu\n", copied + pos);
		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			buf += copied;
			count -= copied;
			iblock = pos >> AEON_SHIFT;
		}

		if (unlikely(copied != bytes)) {
			aeon_err(sb, "%s ERROR!: %p, bytes %lu, copied %lu\n",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}

		if (status < 0)
			break;
	}

	data_bits = 0x1000;
	inode->i_blocks += (new_blocks << (data_bits - sb->s_blocksize_bits));

	ret = written;

	*ppos = pos;
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		pi->i_size = cpu_to_le64(inode->i_size);
	}
out:
	if (ret < 0) {
		aeon_err(sb, "%s error\n", __func__);
		return ret;
	}

	return ret;
}
#endif

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

	if(!iov_iter_count(to))
		return 0;

	inode_lock_shared(inode);
	ret = dax_iomap_rw(iocb, to, &aeon_iomap_ops);
	inode_unlock_shared(inode);

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
	if (ret > 0 && iocb->ki_pos > i_size_read(inode))
		wrap_i_size_write(inode, iocb);

out_unlock:
	inode_unlock(inode);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);

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
#ifdef	CONFIG_AEON_FS_AEON_RW
	.read		= aeon_read,
	.write          = aeon_write,
#endif
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
