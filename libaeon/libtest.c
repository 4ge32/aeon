#include "../aeon.h"
#include "aeon_malloc.h"
#include "aeon_tree.h"

int elements[13] = {1, 7, 21, 14, 56, 70, 81, 99, 42, 86, 3, 80, 35};
int sorted[13] = {1, 3, 7, 14, 21, 35, 42, 56, 70, 80, 81, 86, 99};

static void _do_inorder(struct tt_node *node)
{
	if (!node)
		return;

	_do_inorder(node->tt_left);
	aeon_dbg("%lu\n", node->key);
	_do_inorder(node->tt_right);
}

static void _inorder(struct tt_root *tree)
{
	struct tt_node *root = tree->tt_node;
	aeon_dbg("root %lu\n", root->key);
	_do_inorder(root);
}

static bool _traverse_and_check_tree(struct super_block *sb, int cpu_id,
				     int *origin, int num)
{
	struct aeon_region_table *art;
	struct tt_root *tree;
	struct tt_node *temp;
	struct aeon_range_node *curr;
	bool res = true;
	int i = 0;

	art = aeon_get_rtable(sb, cpu_id);
	tree = &art->block_free_tree;
	temp = tt_first(tree);

	while (temp) {
		if (i >= num) {
			aeon_err(sb, "out of bounds\n");
			aeon_dbg("temp->key %ld\n", temp->key);
			res = false;
			break;
		}

		if (origin[i] == -1) {
			aeon_dbg("deleted %d\n", i);
			goto next;
		}

		curr = container_of(temp, struct aeon_range_node, tt_node);
		if (origin[i] != curr->range_low || temp->key != curr->range_low) {
			aeon_err(sb, "Wrong traverse: ori %d, cur %lu, range %d i %d\n",
				 origin[i], curr->range_low, temp->key, i);
			res = false;
		}
		aeon_dbg("temp->key::key - %lu::%lu\n",
			 temp->key, curr->range_low);
		temp = tt_next(temp);
next:
		i++;
	}

	return res;
}

/* simple insert and traverse test */
bool __test1(struct super_block *sb, int cpu_id)
{
	struct aeon_region_table *art;
	struct aeon_range_node *node;
	struct tt_root *tree;
	int num = sizeof(elements) / sizeof(int);
	int err;
	int i;

	art = aeon_get_rtable(sb, cpu_id);
	if (!art->pmem_pool_addr)
		art->pmem_pool_addr = pmem_create_pool(sb, cpu_id);

	tree = &art->block_free_tree;
	for (i = 0; i < num; i++) {
		node = aeon_pmem_alloc_range_node(sb, cpu_id);
		if (!node) {
			aeon_err(sb, "%s: aeon_pmem_alloc_range_node...\n",
				 __func__);
			return false;
		}
		node->range_low = elements[i];

		err = aeon_pmem_insert_blocktree(&node->tt_node, tree);
		if (err) {
			aeon_err(sb, "%s: aeon_pmem_insert_blocktree...\n",
				 __func__);
			return false;
		}
	}

	if (!_traverse_and_check_tree(sb, cpu_id, sorted, num))
		return false;

	return true;
}

bool __test2(struct super_block *sb, const int cpu_id)
{
	struct aeon_region_table *art;
	struct aeon_range_node *erase_target;
	struct aeon_range_node *node;
	struct tt_root *tree;
	struct tt_node *temp = NULL;
	int target;
	const int num = sizeof(sorted) / sizeof(int);
	int found;
	int err;
	int count = 12;
	int last = 0;

	art = aeon_get_rtable(sb, cpu_id);
	tree = &art->block_free_tree;

loop:
	_inorder(tree);
	target = sorted[count];

	found = tt_find(target, &temp, tree);
	if (!found) {
		aeon_err(sb, "tt_find...\n");
		return false;
	}

	erase_target = container_of(temp, struct aeon_range_node, tt_node);

	err = tt_erase(temp, tree);
	if (err) {
		aeon_err(sb, "tt_erase...\n");
		return false;
	}

	pmem_free(erase_target);
	sorted[count] = -1;

	_inorder(tree);

	if (!_traverse_and_check_tree(sb, cpu_id, sorted, num))
		return false;

	sorted[count] = target;
	aeon_dbg("RE-INSERT: %d %d\n", sorted[count], count);
	node = aeon_pmem_alloc_range_node(sb, cpu_id);
	if (!node) {
		aeon_err(sb, "%s: aeon_pmem_alloc_range_node...\n", __func__);
		return false;
	}
	node->range_low = sorted[count];

	err = aeon_pmem_insert_blocktree(&node->tt_node, tree);
	if (err) {
		aeon_err(sb, "%s: aeon_pmem_insert_blocktree...\n", __func__);
		return false;
	}

	if (!_traverse_and_check_tree(sb, cpu_id, sorted, num))
		return false;

	count--;
	if (count >= last)
		goto loop;

	return true;
}

bool __test3(struct super_block *sb, const int cpu_id)
{
	struct aeon_region_table *art;
	struct tt_root *tree;
	struct tt_node *temp;
	struct tt_node *last = NULL;
	struct aeon_range_node *curr;
	int count = 0;

	art = aeon_get_rtable(sb, cpu_id);
	tree = &art->block_free_tree;
	temp = tt_first(tree);

	while (temp) {
		curr = container_of(temp, struct aeon_range_node, tt_node);
		if (sorted[count] != temp->key || temp->key != curr->range_low) {
			aeon_err(sb, "expected %lu, key %lu:%lu",
				 sorted[count], temp->key, curr->range_low);
			return false;
		}
		last = temp;
		temp = tt_next(temp);
		count++;
	}

	count--;
	temp = last;
	while (temp) {
		curr = container_of(temp, struct aeon_range_node, tt_node);
		if (sorted[count] != temp->key || temp->key != curr->range_low) {
			aeon_err(sb, "expected %lu, key %lu:%lu",
				 sorted[count], temp->key, curr->range_low);
			return false;
		}
		temp = tt_prev(temp);
		count--;
	}

	return true;
}

bool _test(struct super_block *sb)
{
	int cpu_id = 0;

	/* simple insert and traverse test*/
	aeon_info("test 1\n");
	if (!__test1(sb, cpu_id))
		return false;
	aeon_info("test 2\n");
	/* erase and insert test */
	if (!__test2(sb, cpu_id))
		return false;
	/* next and prev test */
	aeon_info("test 3\n");
	if (!__test3(sb, cpu_id))
		return false;
	aeon_info("All OK\n");

	return true;
}
