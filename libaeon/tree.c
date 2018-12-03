#include "../aeon.h"
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

	new->tt_left = NULL;
	new->tt_right = NULL;

	aeon_dbg("INSERT: key %ld parent %ld compval %d\n", new->key, parent->key, compVal);
	return 0;
}

int tt_erase(struct tt_node *target, struct tt_root *tree)
{
	struct tt_node *temp;
	struct tt_node *temp_parent;

	if (!target)
		return -ENOENT;

	aeon_dbg("DELETE TARGET %ld\n", target->key);

	if (target->tt_left && target->tt_right) {
		aeon_dbg("Both\n");
		aeon_dbg("left %ld", target->tt_left->key);
		aeon_dbg("righ %ld", target->tt_right->key);
		aeon_dbg("pare %ld", target->parent->key);
		temp_parent = target;
		temp = target->tt_right;
		while (temp->tt_left) {
			temp_parent = temp;
			temp = temp->tt_left;
		}

		temp->tt_left = target->tt_left;
		if (target->tt_right->parent != target)
			temp->tt_right = target->tt_right;
		temp->parent = target->parent;

		target->tt_left->parent = temp;
		if (target->tt_right != temp)
			target->tt_right->parent = temp;

		if (target->parent->tt_left == target)
			target->parent->tt_left = temp;
		else
			target->parent->tt_right = temp;

		temp_parent->tt_left = NULL;

		aeon_dbg("H! %ld\n", temp->key);
		if (temp->tt_left)
			aeon_dbg("lH! %ld\n", temp->tt_left->key);
		if (temp->tt_right)
			aeon_dbg("rH! %ld\n", temp->tt_right->key);
		if (temp->parent)
			aeon_dbg("pH! %ld\n", temp->parent->key);
		if (temp->parent->tt_left)
			aeon_dbg("plH! %ld\n", temp->parent->tt_left->key);
		if (temp->parent->tt_right)
			aeon_dbg("prH! %ld\n", temp->parent->tt_right->key);

		target = temp;
	} else if (target->tt_left) {
		if (target == tree->tt_node) {
			aeon_dbg("Left1\n");
			tree->tt_node = target->tt_left;
		} else {
			if (target->parent->tt_left == target) {
				aeon_dbg("Left2\n");
				target->parent->tt_left = target->tt_left;
			} else {
				aeon_dbg("Left3\n");
				target->parent->tt_right = target->tt_left;
			}

			target->tt_left->parent = target->parent;
			target->tt_left = NULL;
			target->parent = NULL;
		}
	} else if (target->tt_right) {
		if (target == tree->tt_node) {
			aeon_dbg("Right1\n");
			tree->tt_node = target->tt_right;
			tree->tt_node->parent = NULL;
		} else {
			if (target->parent->tt_left == target) {
				aeon_dbg("Right2\n");
				target->parent->tt_left = target->tt_right;
			} else {
				aeon_dbg("Right3\n");
				target->parent->tt_right = target->tt_right;
			}

			target->tt_right->parent = target->parent;
			target->tt_right = NULL;
			target->parent = NULL;
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
	node->key = curr->range_low;
	return tt_insert(node->key, node, tree);
}
