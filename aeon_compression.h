#ifndef __AEON_COMPRESSION_H
#define __AEON_COMPRESSION_H

#ifdef CONFIG_AEON_FS_COMPRESSION

struct aeon_compress_op {
	struct list_head *(*alloc_workspace)(void);

	void (*free_workspace)(struct list_head *workspace);

	int (*compress_pages)(struct list_head *workspace,
			      struct address_space *mapping,
			      u64 start,
			      struct page **pages,
			      unsigned long *out_pages,
			      unsigned long *total_in,
			      unsigned long *total_out);

	int (*compress_pages_to_pmem)(struct list_head *workspace,
				      const void  *src,
				      const int llen);

	int (*decompress)(struct list_head *workspace,
			  unsigned char *data_in,
			  struct page *dest_page,
			  unsigned long start_byte,
			  size_t srclen, size_t destlen);

	void (*set_level)(struct list_head *ws, unsigned int type);
};

extern void __init aeon_init_compress(void);
extern void __cold aeon_exit_compress(void);
int aeon_compress_data_iter(struct inode *inode, struct iov_iter *i);
ssize_t aeon_decompress_data_iter(ssize_t len, struct iov_iter *i);

#else

static inline void __init aeon_init_compress(void)
{
}
static inline void __cold aeon_exit_compress(void)
{
}
#endif

#endif
