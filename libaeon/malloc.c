#include <linux/module.h>
#include "../aeon.h"
#include "../aeon_balloc.h"

//struct pmem_allocator {
//	u64 curr;
//	u64 next;
//};

struct mem_control_block {
	int is_used;
	int size;
	void *head;
	void *next;
};

#define AEON_OBJ_SIZE		128
#define AEON_RANGE_NODE_SIZE	(AEON_OBJ_SIZE - sizeof(struct mem_control_block))

static void pool_init(void *head)
{
	struct mem_control_block *mcb;
	u64 curr;
	int page_size  = (1<<AEON_SHIFT);
	int num;
	int i;

	num = page_size / AEON_OBJ_SIZE;
	memset(head, 0, page_size);
	for (i = 0; i < num; i++) {
		curr = (u64)head + (i * AEON_OBJ_SIZE);
		mcb = (struct mem_control_block *)curr;
		mcb->is_used = 0;
		mcb->head = (void *)curr;
		if (i != num-1)
			mcb->next = (void *)(curr + AEON_OBJ_SIZE);
		else
			mcb->next = NULL;
		mcb->size = AEON_OBJ_SIZE;
	}
}

static
void *pmem_malloc(struct super_block *sb,
		  int cpu_id, long bytes)
{
	struct aeon_region_table *art;
	struct mem_control_block *mcb;
	void *memory_location;
	u64 current_location;
	u64 addr;

	art = aeon_get_rtable(sb, cpu_id);

	spin_lock(&art->r_lock);

alloc:
	bytes = bytes + sizeof(struct mem_control_block);
	addr = art->pmem_pool_addr + (u64)AEON_SB(sb)->virt_addr;
	current_location = addr;
	memory_location = 0;
	/* FIXME:
	 * Why is the first memory location already used?
	 */
	aeon_dbg("START: %llx\n", current_location);
	do {
		mcb = (struct mem_control_block *)current_location;
		aeon_dbg("%d\n", mcb->is_used);
		aeon_dbg("%d\n", mcb->size);
		if (!mcb->is_used && bytes == mcb->size) {
			aeon_dbg("here:%llx", current_location);
			mcb->is_used = 1;
			memory_location = (void *)current_location;
			break;
		}
		current_location += mcb->size;
	} while (mcb->next);

	if (!memory_location) {
		u64 base_addr = aeon_get_new_blk(sb, cpu_id);
		u64 addr = (u64)AEON_SB(sb)->virt_addr + base_addr;

		pool_init((void *)addr);

		current_location = addr;
		mcb->next = (void *)addr;

		goto alloc;
	}

	memory_location += sizeof(struct mem_control_block);

	spin_unlock(&art->r_lock);

	return memory_location;
}

void *aeon_pmem_alloc_range_node(struct super_block *sb, int cpu_id)
{
	if (cpu_id == ANY_CPU)
		cpu_id = aeon_get_cpuid(sb);

	return pmem_malloc(sb, cpu_id, AEON_RANGE_NODE_SIZE);
}

void pmem_free(void *head)
{
	struct mem_control_block *mcb;
	mcb = head - sizeof(struct mem_control_block);
	mcb->is_used = 0;
}

u64 pmem_create_pool(struct super_block *sb, int cpu_id)
{
	struct aeon_region_table *art = aeon_get_rtable(sb, cpu_id);
	u64 addr;

	aeon_info("cpu_id %d's pool\n", cpu_id);

	spin_lock_init(&art->r_lock);
	addr = aeon_get_new_blk(sb, cpu_id);
	pool_init((void *)(addr + (u64)AEON_SB(sb)->virt_addr));

	return addr;
}
