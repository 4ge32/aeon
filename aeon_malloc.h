#ifndef __AEON_MALLOC_H
#define __AEON_MALLOC_H

void *aeon_pmem_alloc_range_node(struct super_block *, int);
void *pmem_free(void *head);
u64 pmem_create_pool(struct super_block *sb, int cpu_id);

#endif
