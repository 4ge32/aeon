#include <linux/zstd.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/sched/mm.h>
#include <linux/ratelimit.h>
#include <linux/uio.h>

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

static int zstd_decompress(struct list_head *ws, const char *data_in,
			   struct page *dest_page, unsigned long start_byte,
			   size_t srclen, size_t destlen, char *tmp)
{
	struct workspace *workspace = list_entry(ws, struct workspace, list);
	ZSTD_DStream *stream;
	int ret = 0;
	size_t ret2;
	unsigned long total_out = 0;
	unsigned long pg_offset = 0;

	stream = ZSTD_initDStream(ZSTD_AEON_MAX_INPUT,
				  workspace->mem, workspace->size);
	if (!stream) {
		aeon_warn("ZSTD_initDStream failed\n");
		ret = -EIO;
		goto finish;
	}

	destlen = min_t(size_t, destlen, PAGE_SIZE);

	aeon_dbg("%s %lu\n", (char *)data_in, srclen);
	workspace->in_buf.src = data_in;
	workspace->in_buf.pos = 0;
	workspace->in_buf.size = srclen;

	workspace->out_buf.dst = workspace->buf;
	workspace->out_buf.pos = 0;
	workspace->out_buf.size = PAGE_SIZE;

	aeon_dbg("lets decompress\n");

	ret2 = 1;
	while (pg_offset < destlen &&
	       workspace->in_buf.pos < workspace->in_buf.size) {
		unsigned long buf_start;
		unsigned long buf_offset;
		unsigned long bytes;
		int i = 0;

		/* Check if the frame is over and we still need more input */
		if (ret2 == 0) {
			aeon_dbg("ZSTD_decompressStream ended early\n");
			ret = -EIO;
			goto finish;
		}

		aeon_dbg("%d\n", i++);
		ret2 = ZSTD_decompressStream(stream, &workspace->out_buf,
					     &workspace->in_buf);
		aeon_dbg("%d\n", i++);
		if (ZSTD_isError(ret2)) {
			aeon_dbg("heyyy\n");
			ret = -EIO;
			goto finish;
		}

		aeon_dbg("%d\n", i++);
		buf_start = total_out;
		total_out += workspace->out_buf.pos;
		workspace->out_buf.pos = 0;

		aeon_dbg("%d\n", i++);
		if (total_out <= start_byte)
			continue;

		if (total_out > start_byte && buf_start < start_byte)
			buf_offset = start_byte -buf_start;
		else
			buf_offset = 0;

		aeon_dbg("%d\n", i++);
		bytes = min_t(unsigned long, destlen - pg_offset,
			      workspace->out_buf.size - buf_offset);

		/* this is the point which can be changed
		 * when using pmem.
		 * */
		aeon_dbg("%lu\n", total_out);
		memcpy(tmp, workspace->out_buf.dst, total_out);
		aeon_dbg("%s\n", tmp);
		tmp[total_out] = '\0';
		//kaddr = kmap_atomic(dest_page);
		//aeon_dbg("here?\n");
		//memcpy(kaddr + pg_offset,
		//       workspace->out_buf.dst + buf_offset, bytes);
		//aeon_dbg("BUZI\n");
		//kunmap_atomic(kaddr);

		pg_offset += bytes;
	}
	ret = 0;

finish:
	if (pg_offset < destlen) {
		/* Also here */
		//kaddr = kmap_atomic(dest_page);
		//memset(kaddr + pg_offset, 0, destlen - pg_offset);
		//kunmap_atomic(kaddr);
	}
	return ret;
}

const struct aeon_compress_op aeon_zstd_compress = {
	.alloc_workspace	= zstd_alloc_workspace,
	.compress_pages		= zstd_compress_pages,
};

static size_t
zstd_compress_pages_test(struct list_head *ws, const void *src,
			 unsigned long len,
			 unsigned long *out_pages,
			 unsigned long *total_in,
			 unsigned long *total_out, char *tmp)
{
	struct workspace *workspace = list_entry(ws, struct workspace, list);
	ZSTD_CStream *stream;
	size_t ret = 0;
	int nr_pages = 0;
	struct page *in_page = NULL;  /* The current page to read */
	struct page *out_page = NULL; /* The current page to write to */
	unsigned long tot_in = 0;
	unsigned long tot_out = 0;
	const unsigned long nr_dest_pages = *out_pages;
	size_t max_out = nr_dest_pages * PAGE_SIZE;
	ZSTD_parameters params = zstd_get_aeon_parameters(len);

	/**
	 ** struct ZSTD_inBuffer - input buffer for streaming
	 ** @src:  Start of the input buffer.
	 ** @size: Size of the input buffer.
	 ** @pos:  Position where reading stopped. Will be updated.
	 **        Necessarily 0 <= pos <= size.
	 **/
	//typedef struct ZSTD_inBuffer_s {
	//	const void *src;
	//	size_t size;
	//	size_t pos;
	//} ZSTD_inBuffer;
	*out_pages = 0;
	*total_out = 0;
	*total_in = 0;

	stream = ZSTD_initCStream(params, len, workspace->mem, workspace->size);
	if (!stream) {
		aeon_warn("ZSTD_initCStream failed\n");
		ret = -EIO;
		goto out;
	}

	aeon_dbg("1REACH? %s\n", (char *)src);

	workspace->in_buf.src = src;
	workspace->in_buf.pos = 0;
	workspace->in_buf.size = min_t(size_t, len, PAGE_SIZE);

	out_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
	if (out_page == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	nr_pages++;
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

			nr_pages++;
			workspace->out_buf.dst = kmap(out_page);
			workspace->out_buf.pos = 0;
			workspace->out_buf.size = min_t(size_t, max_out,
							PAGE_SIZE);
		}

		/* We've reached the end of the input */
		if (workspace->in_buf.pos >= len) {
			tot_in += workspace->in_buf.pos;
			aeon_dbg("hey come here?\n");
			break;
		}
		/* Check if we need more input */
		// what means need more input?
		if (workspace->in_buf.pos == workspace->in_buf.size) {
			tot_in += PAGE_SIZE;
			kunmap(in_page);
			put_page(in_page);

			len -= PAGE_SIZE;
			// find_get_page could be replaced by something like find_extent
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

		out_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
		if (out_page == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		nr_pages++;
		workspace->out_buf.dst = kmap(out_page);
		workspace->out_buf.pos = 0;
		workspace->out_buf.size = min_t(size_t, max_out, PAGE_SIZE);
	}

	if (tot_out >= tot_in) {
		ret = -E2BIG;
		aeon_dbg("OOPS\n");
		aeon_dbg("%lu %lu\n", tot_out, tot_in);
		goto out;
	}

	ret = tot_out;
	*total_in = tot_in;
	*total_out = tot_out;

	aeon_dbg("------REACH-----?\n");
	aeon_dbg("%s\n", (char *)workspace->in_buf.src);
	aeon_dbg("? %s\n", (char *)kmap(out_page));
	aeon_dbg("? %ld\n", ret);
	memcpy(tmp, kmap(out_page), ret);

out:
	aeon_dbg("OUT\n");
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

const struct aeon_compress_op aeon_zstd_on_pmem_compress = {
	.alloc_workspace	= zstd_alloc_workspace,
};

enum aeon_compression_type {
	AEON_COMPRESS_ZSTD = 0,
	AEON_COMPRESS_ZSTD_ON_PMEM,
	AEON_COMPRESS_TYPES,
};

struct workspace_list {
	struct list_head idle_ws;
	spinlock_t ws_lock;
	int free_ws;
	atomic_t total_ws;
	wait_queue_head_t ws_wait;
};

static struct workspace_list aeon_comp_ws[AEON_COMPRESS_TYPES];

static const struct aeon_compress_op * const aeon_compress_op[] = {
	&aeon_zstd_compress,
	&aeon_zstd_on_pmem_compress,
};

void __init aeon_init_compress(void)
{
	struct list_head *workspace;
	int i;

	for (i = 0; i < AEON_COMPRESS_TYPES; i++) {
		INIT_LIST_HEAD(&aeon_comp_ws[i].idle_ws);
		spin_lock_init(&aeon_comp_ws[i].ws_lock);
		atomic_set(&aeon_comp_ws[i].total_ws, 0);
		init_waitqueue_head(&aeon_comp_ws[i].ws_wait);

		workspace = aeon_compress_op[i]->alloc_workspace();
		if (IS_ERR(workspace))
			aeon_warn("cannot preallocate compression workspace\n");
		else {
			atomic_set(&aeon_comp_ws[i].total_ws, 1);
			aeon_comp_ws[i].free_ws = 1;
			list_add(workspace, &aeon_comp_ws[i].idle_ws);
		}
	}
}

/**
 * This finds an available workspace or allocates a new one.
 * If it is not possible to alllocate a new one, waits until there's one.
 * Preallocation makes a forward progress guarantees and we do not return
 * errors.
 */
static struct list_head *find_workspace(int type)
{
	struct list_head *workspace;
	unsigned nofs_flag;
	int cpus = num_online_cpus();
	int idx = type - 1;
	struct list_head *idle_ws;
	spinlock_t *ws_lock;
	atomic_t *total_ws;
	wait_queue_head_t *ws_wait;
	int *free_ws;

	idle_ws  = &aeon_comp_ws[idx].idle_ws;
	ws_lock  = &aeon_comp_ws[idx].ws_lock;
	total_ws = &aeon_comp_ws[idx].total_ws;
	ws_wait  = &aeon_comp_ws[idx].ws_wait;
	free_ws  = &aeon_comp_ws[idx].free_ws;
again:
	spin_lock(ws_lock);
	if (!list_empty(idle_ws)) {
		workspace = idle_ws->next;
		list_del(workspace);
		(*free_ws)--;
		spin_unlock(ws_lock);
		return workspace;
	}

	if (atomic_read(total_ws) > cpus) {
		DEFINE_WAIT(wait);

		spin_unlock(ws_lock);
		prepare_to_wait(ws_wait, &wait, TASK_UNINTERRUPTIBLE);
		if (atomic_read(total_ws) > cpus && !*free_ws)
			schedule();
		finish_wait(ws_wait, &wait);
		goto again;
	}
	atomic_inc(total_ws);
	spin_unlock(ws_lock);

	nofs_flag = memalloc_nofs_save();
	workspace = aeon_compress_op[idx]->alloc_workspace();
	memalloc_nofs_restore(nofs_flag);

	if (IS_ERR(workspace)) {
		atomic_dec(total_ws);
		wake_up(ws_wait);

		if (atomic_read(total_ws) == 0) {
			static DEFINE_RATELIMIT_STATE(_rs,
					/* once per minute */ 60 * HZ,
					/* no burst */ 1);

			if (__ratelimit(&_rs))
				pr_warn("BTRFS: no compression workspaces, low memory, retrying\n");
		}
		goto again;
	}

	return workspace;
}

static void free_workspace(int type, struct list_head *workspace)
{
	struct list_head *idle_ws;
	spinlock_t *ws_lock;
	atomic_t *total_ws;
	wait_queue_head_t *ws_wait;
	int *free_ws;
	int idx = type - 1;

	idle_ws  = &aeon_comp_ws[idx].idle_ws;
	ws_lock  = &aeon_comp_ws[idx].ws_lock;
	total_ws = &aeon_comp_ws[idx].total_ws;
	ws_wait  = &aeon_comp_ws[idx].ws_wait;
	free_ws  = &aeon_comp_ws[idx].free_ws;

	spin_lock(ws_lock);
	if (*free_ws <= num_online_cpus()) {
		list_add(workspace, idle_ws);
		(*free_ws)++;
		spin_unlock(ws_lock);
		goto wake;
	}
	spin_unlock(ws_lock);

	aeon_compress_op[idx]->free_workspace(workspace);
	atomic_dec(total_ws);
wake:
	if (wq_has_sleeper(ws_wait))
		wake_up(ws_wait);
}

static void free_workspaces(void)
{
	struct list_head *workspace;
	int i;

	for (i = 0; i < AEON_COMPRESS_TYPES; i++) {
		while (!list_empty(&aeon_comp_ws[i].idle_ws)) {
			workspace = aeon_comp_ws[i].idle_ws.next;
			list_del(workspace);
			/* TODO: Define it */
			//aeon_compress_op[i]->free_workspace(workspace);
			atomic_dec(&aeon_comp_ws[i].total_ws);
		}
	}
}

void __cold aeon_exit_compress(void)
{
	free_workspaces();
}

static const char* const aeon_compress_types[] = { "zstd" };

/**
 * Given an address space and start and length, compress the bytes into @pages
 * that are allocated on demand.
 *
 * @type_level is encoded algorithm and level, where level 0 means whatever
 * default the algorithm chooses and is opaque here;
 * - compression algo are 0-3
 * - the level are bits 4-7
 *
 * @out_pages is an in/out parameter, holds maximum number of pages to allocate
 * and returns number of actually allocated pages
 *
 * @total_in is used to return the number of bytes actually read. It may be
 * smaller than the input length if we had to exit early because we ran out of
 * room in the pages array or because we cross the max_out threshold.
 *
 * @total_out is an in/out parameter, must be set to the input length and will
 * be also used to return the total number of compressed bytes
 *
 * @max_out tells us the max number of bytes that we're allowed to
 * stuff into pages
 */
int aeon_compress_pages(unsigned int type_level, struct address_space *mapping,
			u64 start, struct page **pages,
			unsigned long *out_pages,
			unsigned long *total_in,
			unsigned long *total_out)
{
	struct list_head *workspace;
	int ret;
	int type = type_level & 0xF;

	workspace = find_workspace(type);
	ret = aeon_compress_op[type-1]->compress_pages(workspace, mapping,
						       start, pages,
						       out_pages,
						       total_in, total_out);
	free_workspace(type, workspace);
	return ret;
}

static int aeon_compress_pmem(void *src, struct iov_iter *i)
{
	struct list_head *workspace;
	unsigned long len = i->count;
	unsigned long out_pages = (len >> PAGE_SHIFT) + 1;
	unsigned long total_in = 0;
	unsigned long total_out = 0;
	int type = 1 & 0xF;
	size_t ret;
	char tmp[1000];

	struct page dest_page;

	aeon_dbg("----start-------------\n");
	aeon_dbg("%s", (char *)src);
	aeon_dbg("%lu\n", len);
	workspace = find_workspace(type);
	ret = zstd_compress_pages_test(workspace, src, len,
				       &out_pages, &total_in, &total_out, tmp);
	free_workspace(type, workspace);

	aeon_dbg("----end-------------\n");
	aeon_dbg("%s", (char *)src);
	aeon_dbg("%s", (char *)tmp);
	aeon_dbg("%lu\n", ret);

	aeon_dbg("%lu %lu %lu\n", out_pages, total_in, total_out);

	//workspace = find_workspace(type);
	//ret = zstd_decompress(workspace, tmp, &dest_page, 0, ret, 4096, tmp);
	//free_workspace(type, workspace);
	//aeon_dbg("----FINISH------\n");
	i->count = ret;
	tmp[i->count] = '\0';
	memcpy(src, tmp, i->count+1);
	aeon_dbg("src %s\n", (char *)src);

	return 0;
}

int aeon_compress_data_iter(struct iov_iter *i)
{
	char *buf;
	int err = 0;

	if (!i->count)
		goto out;

	buf = kzalloc(sizeof(char) * (i->count+1), GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto out1;
	}

	if (unlikely(i->type & ITER_BVEC)) {
		aeon_dbg("1!\n");
	} else if (unlikely(i->type & ITER_KVEC)) {
		aeon_dbg("2!\n");
	} else {
		size_t tmp;
		aeon_dbg("3!\n");

		err = copy_from_user(buf, i->iov->iov_base, i->count);
		if (err) {
			AEON_ERR();
			goto out1;
		}
		buf[i->count] = '\0';
		tmp = i->count;

		err = aeon_compress_pmem(buf, i);
		if (err) {
			AEON_ERR();
			goto out1;
		}

		aeon_dbg("new %lu\n", i->count);
		aeon_dbg("buf %s\n", buf);
		err = copy_to_user(i->iov->iov_base, buf, i->count+1);
		if (err) {
			AEON_ERR();
			goto out1;
		}
		aeon_dbg("RES\n");
	}


out1:
	kfree(buf);
	buf = NULL;
out:
	return err;
}
