#include "aeon.h"
#include "aeon_tree.h"
#include "aeon_malloc.h"


static int compare_node(struct tt_node *node, unsigned long key)
{
	if (key < node->key)
		return -1;
	else if (key > node->key)
		return 1;
	return 0;
}

struct tt_node *tt_next(const struct tt_node *node)
{
	struct tt_node *parent;

	if (node->tt_right) {
		node = node->tt_right;
		while (node->tt_left)
			node = node->tt_left;
		return (struct tt_node *)node;
	}

	while ((parent = tt_parent(node)) && node == parent->tt_right)
		node = parent;

	return parent;
}

struct tt_node *tt_first(const struct tt_root *tree)
{
	struct tt_node *node = tree->tt_node;

	if (!node)
		return NULL;

	while (node->tt_left)
		node = node->tt_left;

	return node;
}

int tt_find(unsigned long key, struct tt_node **ret, struct tt_root *tree)
{
	struct tt_node *temp;
	struct tt_node *root = tree->tt_node;
	int compVal;
	int found = 0;

	temp = root;
	while (temp) {
		compVal = compare_node(temp, key);
		if (compVal == -1)
			temp = temp->tt_left;
		else if (compVal == 1)
			temp = temp->tt_right;
		else {
			found = 1;
			break;
		}
	}

	*ret = temp;
	return found;
}

int tt_insert(unsigned long key, struct tt_node *new, struct tt_root *tree)
{
	struct tt_node *temp;
	struct tt_node *parent;
	int compVal;

	if (!tree->tt_node) {
		tree->tt_node = new;
		return 0;
	}

	temp = tree->tt_node;
	while (temp) {
		parent = temp;
		compVal = compare_node(temp, key);
		aeon_dbg("temp->key %lu key %lu\n", temp->key, key);
		if (compVal == -1)
			temp = temp->tt_left;
		else if (compVal == 1)
			temp = temp->tt_right;
		else {
			pr_info("Already exists - key:%lu\n", key);
			return -EINVAL;
		}
	}

	temp = new;
	temp->parent = parent;
	if (compVal == -1)
		temp->parent->tt_left = temp;
	else
		temp->parent->tt_right = temp;

	return 0;
}

int tt_erase(struct tt_node *target, struct tt_root *tree)
{
	struct tt_node *temp;
	struct tt_node *temp_parent;

	if (!target)
		return -ENOENT;

	if (target->tt_left && target->tt_right) {
		temp_parent = target;
		temp = target->tt_right;
		while (temp->tt_left) {
			temp_parent = temp;
			temp = temp->tt_left;
		}

		target = temp;
	} else if (target->tt_left) {
		if (target == tree->tt_node)
			tree->tt_node = target->tt_left;
		else {
			if (target->parent->tt_left == target)
				target->parent->tt_left = target->tt_left;
			else
				target->parent->tt_right = target->tt_left;

			target->tt_left->parent = target->parent;
		}
	} else if (target->tt_right) {
		if (target == tree->tt_node) {
			aeon_dbg("Right1\n");
			tree->tt_node = target->tt_right;
		}
		else {
			if (target->parent->tt_left == target) {
				aeon_dbg("Right2\n");
				target->parent->tt_left = target->tt_left;
			}
			else {
				aeon_dbg("Right3\n");
				target->parent->tt_right = target->tt_left;
			}

			target->tt_right->parent = target->parent;
		}
	} else {
		if (!target->parent) {
			aeon_dbg("LAST1\n");
			tree->tt_node = NULL;
		}
		else if (target->parent->tt_left == target) {
			aeon_dbg("LAST2\n");
			target->parent->tt_left = NULL;
		}
		else {
			aeon_dbg("LAST3\n");
			target->parent->tt_right = NULL;
		}
	}

	return 0;
}

int aeon_pmem_insert_blocktree(struct tt_node *node, struct tt_root *tree)
{
	struct aeon_range_node *curr;

	curr = container_of(node, struct aeon_range_node, tt_node);
	aeon_dbg("!! %lu\n", curr->range_low);
	node->key = curr->range_low;
	return tt_insert(node->key, node, tree);
}
