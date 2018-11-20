#ifndef __AEON_MALLOC_H
#define __AEON_MALLOC_H

void *pmem_malloc(struct super_block *sb, unsigned long bytes);
void *pmem_free(void *head);
void *pmem_create_pool(struct super_block *sb);

#endif
