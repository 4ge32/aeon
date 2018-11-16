/*
 * BRIEF DESCRIPTION
 *
 * Memory protection definitions for the AEON filesystem.
 *
 * Copyright 2018 Fumiya Shigemitsu <shfy1014@gmail.com>
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */
#ifndef __WPROTECT_H
#define __WPROTECT_H

#include <linux/fs.h>

static inline int aeon_range_check(struct super_block *sb, void *p,
				   unsigned long len)
{
	struct aeon_sb_info *sbi = AEON_SB(sb);

	if (p < sbi->virt_addr ||
	    p + len > sbi->virt_addr + sbi->initsize) {
		aeon_err(sb, "access pmem out of range: pmem range 0x%lx - 0x%lx, "
			 "access range 0x%lx - 0x%lx\n",
			 (unsigned long)sbi->virt_addr,
			 (unsigned long)(sbi->virt_addr + sbi->initsize),
			 (unsigned long)p, (unsigned long)(p + len));
		dump_stack();
		return -EINVAL;
	}

	return 0;
}

extern int aeon_writeable(void *, unsigned long size, int rw);

static inline void
__aeon_memunlock_range(void *p, unsigned long len)
{
	aeon_writeable(p, len, 1);
}

static inline void
__aeon_memlock_range(void *p, unsigned long len)
{
	aeon_writeable(p, len, 0);
}

static inline int aeon_is_protected(struct super_block *sb)
{
	struct aeon_sb_info *sbi = (struct aeon_sb_info *)sb->s_fs_info;

	if (wprotect)
		return wprotect;

	return sbi->s_mount_opt & AEON_MOUNT_PROTECT;
}

static inline void aeon_memlock_inode(struct super_block *sb,
				      struct aeon_inode *pi)
{
	if (aeon_is_protected(sb))
		__aeon_memlock_range(pi, AEON_INODE_SIZE);
}

static inline void aeon_memunlock_inode(struct super_block *sb,
					struct aeon_inode *pi)
{
	if (aeon_range_check(sb, pi, AEON_INODE_SIZE))
		return;

	if (aeon_is_protected(sb))
		__aeon_memunlock_range(pi, AEON_INODE_SIZE);
}

static inline void aeon_memlock_super(struct super_block *sb)
{
	struct aeon_super_block *ps = aeon_get_super(sb);

	if (aeon_is_protected(sb))
		__aeon_memlock_range(ps, AEON_SB_SIZE);
}

static inline void aeon_memunlock_super(struct super_block *sb)
{
	struct aeon_super_block *ps = aeon_get_super(sb);

	if (aeon_is_protected(sb))
		__aeon_memunlock_range(ps, AEON_SB_SIZE);
}
#endif
