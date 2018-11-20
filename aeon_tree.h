#ifndef __AEON_TREE_H
#define __AEON_TREE_H

/*
 * tt means test tree - it aims to become a good data structure
 * for using on a non-volatile memory in AEON.
 */

struct tt_node {
	void *data;
	unsigned long key;
	struct tt_node *tt_right;
	struct tt_node *tt_left;
};

struct tt_root {
	struct tt_node *tt_node;
};

#define TT_ROOT (struct tt_root) { NULL, }

struct tt_node *tt_next(const struct tt_node *);
struct tt_node *tt_prev(const struct tt_node *);
struct tt_node *tt_first(const struct tt_root *);

int tt_insert(struct tt_node *, struct tt_root *);

#endif
