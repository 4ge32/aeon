#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>

#include "aeon.h"
#include "aeon_balloc.h"
#include "aeon_extents.h"
#include "aeon_compression.h"

ssize_t do_dax_decompress_read(struct inode *inode, char __user *buf,
			       size_t len, loff_t *ppos)
{
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	ssize_t offset;
	ssize_t index;
	ssize_t end_index;
	ssize_t copied = 0;
	loff_t pos;
	loff_t isize;
	ssize_t err = 0;

	aeon_dbgv("-----READ-----\n");
	aeon_dbgv("INO: %lu\n", inode->i_ino);

	pos = *ppos;
	index = pos >> PAGE_SHIFT;
	offset = pos;
	isize = le64_to_cpu(pi->i_original_size);

	if (isize == 0)
		goto out;

	if (len > isize - pos)
		len = isize - pos;
	if (len <= 0)
		goto out;

	aeon_dbgv("len     %lu \n", len);
	aeon_dbgv("isize   %lld \n", isize);
	aeon_dbgv("pos     %lld \n", pos);

	end_index = (isize - 1) >> PAGE_SHIFT;

	aeon_dbgv("start   %lu \n", index);
	aeon_dbgv("end     %lu \n", end_index);

	do {
		struct aeon_extent *ae;
		unsigned long nr;
		unsigned long left;
		unsigned long blocknr;
		unsigned long ex_offset;
		ssize_t copying;
		void *nvmm;
		void *dram;
		int pages;
		int index_extent = 0;

		if (index >= end_index) {
			if (index > end_index)
				goto out;

			nr = ((isize - 1) & ~PAGE_MASK) + 1;
		}

		aeon_dbgv("---PREPARE  \n");
		aeon_dbgv("start   %lu \n", index);
		aeon_dbgv("end     %lu \n", end_index);

		ae = aeon_search_cextent(sb, sih, pos);
		if (!ae) {
			aeon_err(sb, "can't find an extent: %u\n", index);
			goto out;
		}
		ex_offset = le32_to_cpu(ae->ex_original_offset);
		if (offset < le32_to_cpu(ae->ex_offset)<<PAGE_SHIFT)
			offset = 0;
		else
			offset -= le32_to_cpu(ae->ex_original_offset);
		blocknr = le64_to_cpu(ae->ex_block);
		index_extent = le16_to_cpu(ae->ex_index);
		pages = le16_to_cpu(ae->ex_length) - (index-ex_offset);
		nvmm = aeon_get_address(sb, blocknr<<AEON_SHIFT, 0);

		aeon_dbgv("exindex %d\n", le16_to_cpu(ae->ex_index));
		aeon_dbgv("block   %lu\n", blocknr);
		aeon_dbgv("exoffc  %lu\n", ex_offset);
		aeon_dbgv("exoffo  %u\n", le32_to_cpu(ae->ex_offset));
		aeon_dbgv("exind   %d\n", index_extent);
		aeon_dbgv("lengt   %d\n", le16_to_cpu(ae->ex_original_length));
		aeon_dbgv("nvmm  0x%llx\n", (u64)nvmm);

		if (le32_to_cpu(ae->ex_compressed))
			dram = aeon_decompress(nvmm, ae, pi);
		else
			dram = nvmm;
		if (IS_ERR(dram)) {
			aeon_err(sb, "can't decompress data\n");
			goto out;
		}

		copying = le32_to_cpu(ae->ex_original_offset) +
			le32_to_cpu(ae->ex_original_length) - pos;
		if (len < copying + copied)
			nr = len - copied;
		else
			nr = copying;

		aeon_dbgv("---COPYING");
		aeon_dbgv("o_len   %u\n", le32_to_cpu(ae->ex_original_length));
		aeon_dbgv("copied  %lu\n", copied);
		aeon_dbgv("copying %lu\n", copying);
		aeon_dbgv("offset  %lu\n", offset);
		aeon_dbgv("nr      %lu\n", nr);
		aeon_dbgv("addr  0x%llx\n", (u64)dram+offset);

		left = copy_to_user(buf+copied, dram+offset, nr);

		copied += (nr - left);
		offset += (nr - left);
		index += (offset >> AEON_SHIFT);
		pos += (nr - left);

		aeon_dbgv("---DONE    \n");
		aeon_dbgv("le      %lu\n", len);
		aeon_dbgv("left    %lu\n", left);
		aeon_dbgv("copied  %lu\n", copied);
		aeon_dbgv("offset  %ld\n", offset);
		aeon_dbgv("now     %llu\n", pos);

		if (copied < len) {
			aeon_dbgv("COPY MORE\n");
			goto out;
		}

		if (le32_to_cpu(ae->ex_compressed))
			kfree(dram);
	} while (copied < len);

out:
	*ppos = pos;

	aeon_dbgv("POS		     %llu", *ppos);
	aeon_dbgv("copied return     %lu\n", copied);
	return copied ? copied : err;
}

static int do_get_new_blocks_vc(struct super_block *sb,
				struct inode *inode,
				struct aeon_inode_info_header *sih,
				unsigned long iblock,
				unsigned long num_blocks,
				unsigned long *ret_blocknr,
				unsigned long original_len, int compressed)
{
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	struct aeon_extent_header *aeh;
	unsigned long blocknr = 0;
	int o_len = (original_len + (1<<PAGE_SHIFT) - 1) >> PAGE_SHIFT;
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

	err = aeon_update_cextent(sb, inode, blocknr, iblock, o_len,
				  num_blocks, original_len,
				  compressed, allocated);
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

ssize_t aeon_compress_write(struct file *filp, const char __user *buf,
			    size_t len, loff_t *ppos)
{
	struct inode *inode = filp->f_mapping->host;
	struct super_block *sb = inode->i_sb;
	struct aeon_inode_info_header *sih = &AEON_I(inode)->header;
	struct aeon_inode *pi = aeon_get_inode(sb, sih);
	unsigned long blocknr;
	unsigned long num_blocks; /* The num of blocks used for the file data */
	unsigned long iblock;	  /* file offset in block */
	unsigned long offset;     /* file offset in bytes */
	unsigned long copied;
	unsigned long status;
	unsigned long outlen = 0;
	ssize_t ret = -EFAULT;
	ssize_t written = 0;
	ssize_t count;		  /* entire written bytes to the file */
	ssize_t space;
	ssize_t bytes;
	size_t original_len;
	int allocated;
	int compressed = 0;
	loff_t pos;
	void *nvmm;
	void *compressed_data = NULL;
	void *head = NULL;
	u64 addr_off;

	if (!access_ok(VERIFY_READ, buf, len))
		return -EFAULT;

	ret = file_remove_privs(filp);
	if (ret)
		goto out;

	pos = *ppos;
	if (filp->f_flags & O_APPEND)
		pos = i_size_read(inode);

	inode->i_ctime = inode->i_mtime = current_time(inode);

	compressed_data = aeon_compress(buf, len, &outlen, &compressed);
	if (IS_ERR(compressed_data)) {
		aeon_err(sb, "failed to compress data\n");
		goto out;
	}
	head = compressed_data;
	original_len = len;
	len = outlen;

	count = len;
	iblock = pos >> AEON_SHIFT;
	offset = pos;

	aeon_dbgv("---WRITE---\n");
	aeon_dbgv("INO: %lu\n", inode->i_ino);
	aeon_dbgv("outlen   %lu\n", outlen);
	aeon_dbgv("len      %lu\n", len);
	aeon_dbgv("pos      %llu\n", pos);
	aeon_dbgv("iblock   %lu\n", iblock);
	aeon_dbgv("offset   %lu\n", offset);

	while (count > 0) {
		aeon_dbgv("-START-\n");

		num_blocks = ((count - 1) >> AEON_SHIFT) + 1;

		//ae = aeon_search_cextent(sb, sih, iblock);
		//if (!ae) {
		//	aeon_dbgv("Allocate new blocks\n");

		//	allocated = do_get_new_blocks_vc(sb, inode, sih, iblock,
		//					 num_blocks, &blocknr,
		//					 original_len);
		//	if (allocated <= 0) {
		//		ret = -ENOSPC;
		//		goto out;
		//	}

		//	offset = 0;
		//	space = sb->s_blocksize * allocated - offset;
		//} else {
		//	aeon_dbgv("Use remaining space\n");

		//	blocknr = le64_to_cpu(ae->ex_block);
		//	allocated = le32_to_cpu(ae->ex_original_length);
		//	aeon_dbgv("eoffset  %lu->\n", offset);
		//	offset -= sb->s_blocksize * le32_to_cpu(ae->ex_original_offset);

		//	aeon_dbgv("offset   %u\n", le32_to_cpu(ae->ex_original_offset));
		//	space = sb->s_blocksize * allocated - offset;
		//}
		aeon_dbgv("Allocate new blocks");
		allocated = do_get_new_blocks_vc(sb, inode, sih, iblock,
						 num_blocks, &blocknr,
						 original_len, compressed);
		if (allocated <= 0) {
			ret = -ENOSPC;
			goto out;
		}

		offset = pos & ~PAGE_MASK;
		space = sb->s_blocksize * allocated - offset;

		aeon_dbgv("allocate %d\n", allocated);
		aeon_dbgv("blocknr  %lu\n", blocknr);
		aeon_dbgv("pos      %llu\n", pos);
		aeon_dbgv("count    %lu\n", count);
		aeon_dbgv("offset   %lu\n", offset);
		aeon_dbgv("space    %lu\n", space);

		bytes = sb->s_blocksize * allocated - offset;
		aeon_dbgv("bytes    %lu\n", bytes);
		if (bytes > count)
			bytes = count;
		if (bytes > space)
			bytes = space;

		addr_off = blocknr << AEON_SHIFT;
		nvmm = aeon_get_address(sb, addr_off, 0);

		aeon_dbgv("nvmm     0x%llx\n", (u64)nvmm);
		aeon_dbgv("offset   %lu\n", offset);
		aeon_dbgv("bytes    %lu\n", bytes);
		aeon_dbgv("COPY\n");

		copied = bytes - memcpy_to_pmem_nocache(nvmm+offset,
							compressed_data, bytes);
		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			compressed_data += copied;
			count -= copied;
			iblock = pos >> AEON_SHIFT;
		}

		aeon_dbgv("copied   %lu\n", copied);
		aeon_dbgv("offset   %lu\n", offset);
		aeon_dbgv("bytes    %lu\n", bytes);
		aeon_dbgv("pos      %llu\n", pos);
		aeon_dbgv("count    %lu\n", count);

		if (unlikely(copied != bytes)) {
			aeon_err(sb, "%s ERROR!: %p, bytes %lu, copied %lu\n",
				__func__, nvmm, bytes, copied);
			BUG();
			if (status >= 0)
				status = -EFAULT;
		}

		if (status < 0)
			break;
	}

	aeon_dbgv("NOW   %llu/n", pos >> AEON_SHIFT);
	*ppos = pos;
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		pi->i_size = cpu_to_le64(pos);
		pi->i_original_size += cpu_to_le64(original_len);
	}

	ret = original_len;
out:
	if (head)
		kfree(head);
	return ret;
}
