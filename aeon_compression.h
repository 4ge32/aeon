#ifndef __AEON_COMPRESSION_H
#define __AEON_COMPRESSION_H

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

	int (*decompress)(struct list_head *workspace,
			  unsigned char *data_in,
			  struct page *dest_page,
			  unsigned long start_byte,
			  size_t srclen, size_t destlen);

	void (*set_level)(struct list_head *ws, unsigned int type);
};


#endif
