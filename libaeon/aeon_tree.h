#ifndef __AEON_TREE_H
#define __AEON_TREE_H

/*
 * tt means test tree - it aims to become a good data structure
 * for using on a non-volatile memory in AEON.
 */

struct tt_node {
	unsigned long key;
	struct tt_node *parent;
	struct tt_node *tt_right;
	struct tt_node *tt_left;
};

struct tt_root {
	struct tt_node *tt_node;
};

static inline
struct tt_node *tt_parent(const struct tt_node *node)
{
	return node->parent;
}

#define TT_ROOT (struct tt_root) {NULL, }

struct tt_node *tt_next(const struct tt_node *);
struct tt_node *tt_prev(const struct tt_node *);
struct tt_node *tt_first(const struct tt_root *);

int tt_find(unsigned long, struct tt_node **, struct tt_root *);
int tt_erase(struct tt_node *, struct tt_root *);

int aeon_pmem_insert_blocktree(struct tt_node *, struct tt_root *);

#endif

