#ifndef __AEON_EXTENTS_H
#define __AEON_EXTENTS_H

#include "aeon_inode.h"

static inline
struct aeon_extent_header *aeon_get_extent_header(struct aeon_inode *pi)
{
	return &pi->aeh;
}

static inline
void aeon_init_extent_header(struct aeon_extent_header *aeh)
{
	aeh->eh_entries = 0;
	aeh->eh_depth = 0;
	aeh->eh_blocks = 0;
	memset(aeh->eh_extent_blocks, 0, sizeof(aeh->eh_extent_blocks));
}

u64 aeon_pull_extent_addr(struct super_block *sb,
			  struct aeon_inode_info_header *sih, int index);
int aeon_delete_extenttree(struct super_block *sb,
			   struct aeon_inode_info_header *sih);
int aeon_cutoff_extenttree(struct super_block *sb,
			   struct aeon_inode_info_header *sih,
			   struct aeon_inode *pi, int remaining, int index);
struct aeon_extent *aeon_search_extent(struct super_block *sb,
				       struct aeon_inode_info_header *sih,
				       unsigned long iblock);
int aeon_update_extent(struct super_block *sb, struct inode *inode,
		       unsigned blocknr, unsigned long offset, int num_blocks);
#endif
