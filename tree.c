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

struct tt_node *tt_first(const struct tt_root *root)
{
	return root->tt_node;
}

int tt_insert(struct tt_node *new, struct tt_root *root)
{
	struct tt_node *temp;
	struct tt_node *node = root->tt_node;
	int compVal;
	int key;

	if (!node) {
		root->tt_node = new;
		return 0;
	}

	key = new->key;
	temp = node;
	while (temp) {
		compVal = compare_node(temp, key);
		if (compVal == -1)
			temp = temp->tt_left;
		else if (compVal == 1)
			temp = temp->tt_right;
		else {
			pr_info("Already exists\n");
			return -EINVAL;
		}
	}

	temp = new;

	return 0;
}
