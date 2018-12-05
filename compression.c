#include <linux/zstd.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagemap.h>

#include "aeon.h"
#include "aeon_compression.h"

struct workspace {
	void *mem;
	size_t size;
	char *buf;
	struct list_head list;
	ZSTD_inBuffer in_buf;
	ZSTD_outBuffer out_buf;
};

#define ZSTD_AEON_MAX_WINDOWLOG 17
#define ZSTD_AEON_MAX_INPUT	(1 << ZSTD_AEON_MAX_WINDOWLOG)
#define ZSTD_AEON_DEFAULT_LEVEL 1

static ZSTD_parameters zstd_get_aeon_parameters(size_t src_len)
{
	ZSTD_parameters params = ZSTD_getParams(ZSTD_AEON_DEFAULT_LEVEL,
						src_len, 0);
	if (params.cParams.windowLog > ZSTD_AEON_MAX_WINDOWLOG)
		params.cParams.windowLog = ZSTD_AEON_MAX_WINDOWLOG;
	return params;
}

static void zstd_free_workspace(struct list_head *ws)
{
	struct workspace *workspace = list_entry(ws, struct workspace, list);

	kvfree(workspace->mem);
	kfree(workspace->buf);
	kfree(workspace);
}

static struct list_head *zstd_alloc_workspace(void)
{
	ZSTD_parameters params = zstd_get_aeon_parameters(ZSTD_AEON_MAX_INPUT);
	struct workspace *workspace;

	workspace = kzalloc(sizeof(struct workspace), GFP_KERNEL);
	if (!workspace)
		return ERR_PTR(-ENOMEM);

	workspace->size = max_t(size_t,
			ZSTD_CStreamWorkspaceBound(params.cParams),
			ZSTD_DStreamWorkspaceBound(1<<17));
	workspace->mem = kvmalloc(workspace->size, GFP_KERNEL);
	workspace->buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!workspace->mem || !workspace->buf)
		goto fail;

	INIT_LIST_HEAD(&workspace->list);

	return &workspace->list;

fail:
	zstd_free_workspace(&workspace->list);
	return ERR_PTR(-ENOMEM);
}

static int zstd_compress_pages(struct list_head *ws,
			       struct address_space *mapping,
			       u64 start, struct page **pages,
			       unsigned long *out_pages,
			       unsigned long *total_in,
			       unsigned long *total_out)
{
	struct workspace *workspace = list_entry(ws, struct workspace, list);
	ZSTD_CStream *stream;
	int ret = 0;
	int nr_pages = 0;
	struct page *in_page = NULL;  /* The current page to read */
	struct page *out_page = NULL; /* The current page to write to */
	unsigned long tot_in = 0;
	unsigned long tot_out = 0;
	unsigned long len = *total_out;
	const unsigned long nr_dest_pages = *out_pages;
	unsigned long max_out = nr_dest_pages * PAGE_SIZE;
	ZSTD_parameters params = zstd_get_aeon_parameters(len);

	*out_pages = 0;
	*total_out = 0;
	*total_in = 0;

	/* Initialize the stream */
	stream = ZSTD_initCStream(params, len, workspace->mem, workspace->size);
	if (!stream) {
		aeon_warn("ZSTD_initCStream failed\n");
		ret = -EIO;
		goto out;
	}

	/* map in the first page of input data */
	/**
	 * find_get_page - find and get a page reference
	 */
	in_page = find_get_page(mapping, start >> PAGE_SHIFT);
	// here could be changed
	workspace->in_buf.src = kmap(in_page);
	workspace->in_buf.pos = 0;
	workspace->in_buf.size = min_t(size_t, len, PAGE_SIZE);

	/* Allocate and map in the output buffer */
	out_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
	if (out_page == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	pages[nr_pages++] = out_page;
	workspace->out_buf.dst = kmap(out_page);
	workspace->out_buf.pos = 0;
	workspace->out_buf.size = min_t(size_t, max_out, PAGE_SIZE);

	while (1) {
		size_t ret2;

		ret2 = ZSTD_compressStream(stream, &workspace->out_buf,
					   &workspace->in_buf);
		if (ZSTD_isError(ret2)) {
			aeon_dbg("ZSTD_compressionStream returned %d\n",
				 ZSTD_getErrorCode(ret2));
			ret = -EIO;
			goto out;
		}

		/* Check to see if we are making it bigger */
		if (tot_in + workspace->in_buf.pos > 8192 &&
		    tot_in + workspace->in_buf.pos <
		    tot_out + workspace->out_buf.pos) {
			ret = -E2BIG;
			goto out;
		}

		/* Check if we need more output space */
		if (workspace->out_buf.pos == workspace->out_buf.size) {
			tot_out += PAGE_SIZE;
			max_out -= PAGE_SIZE;
			// here should be replaced by another one
			kunmap(out_page);
			if (nr_pages == nr_dest_pages) {
				out_page = NULL;
				ret = -E2BIG;
				goto out;
			}

			out_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
			if (out_page == NULL) {
				ret = -ENOMEM;
				goto out;
			}
			pages[nr_pages++] = out_page;
			workspace->out_buf.dst = kmap(out_page);
			workspace->out_buf.pos = 0;
			workspace->out_buf.size = min_t(size_t, max_out,
							PAGE_SIZE);
		}

		/* We've reached the end of the input */
		if (workspace->in_buf.pos >= len) {
			tot_in += workspace->in_buf.pos;
			break;
		}

		/* Check if we need more input */
		// what means need more input?
		if (workspace->in_buf.pos == workspace->in_buf.size) {
			tot_in += PAGE_SIZE;
			kunmap(in_page);
			put_page(in_page);

			start += PAGE_SIZE;
			len -= PAGE_SIZE;
			// find_get_page could be replaced by something like find_extent
			in_page = find_get_page(mapping, start >> PAGE_SHIFT);
			workspace->in_buf.src = kmap(in_page);
			workspace->in_buf.pos = 0;
			workspace->in_buf.size = min_t(size_t, len, PAGE_SIZE);
		}
	}

	while (1) {
		size_t ret2;

		ret2 = ZSTD_endStream(stream, &workspace->out_buf);
		if (ZSTD_isError(ret2)) {
			aeon_warn("ZSTD_endstream returned %d\n",
				  ZSTD_getErrorCode(ret2));
			ret = -EIO;
			goto out;
		}

		if (ret2 == 0) {
			tot_out += workspace->out_buf.pos;
			break;
		}

		if (workspace->out_buf.pos > max_out) {
			tot_out += workspace->out_buf.pos;
			ret = -E2BIG;
			goto out;
		}

		tot_out += PAGE_SIZE;
		max_out -= PAGE_SIZE;
		kunmap(out_page);
		if (nr_pages == nr_dest_pages) {
			out_page = NULL;
			ret = -E2BIG;
			goto out;
		}

		out_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
		if (out_page == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		pages[nr_pages++] = out_page;
		workspace->out_buf.dst = kmap(out_page);
		workspace->out_buf.pos = 0;
		workspace->out_buf.size = min_t(size_t, max_out, PAGE_SIZE);
	}

	if (tot_out >= tot_in) {
		ret = -E2BIG;
		goto out;
	}

	ret = 0;
	*total_in = tot_in;
	*total_out = tot_out;

out:
	*out_pages = nr_pages;
	/* Cleanup */
	if (in_page) {
		kunmap(in_page);
		put_page(in_page);
	}

	if (out_page)
		kunmap(out_page);

	return ret;
}

const struct aeon_compress_op aeon_zstd_compress = {
	.alloc_workspace	= zstd_alloc_workspace,
	.compress_pages		= zstd_compress_pages,
};
