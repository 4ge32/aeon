#include <linux/module.h>
#include "aeon.h"

int has_initialized = 0;
void *managed_memory_start;
void *last_valid_address;

struct allocator_state {
	int initialized;
	void *head;
	void *last;
};

struct mem_control_block {
	int is_used;
	int size;
};

static void malloc_init(struct super_block *sb)
{
	struct mem_control_block *mcb;
	u64 base_addr = aeon_get_new_blk(sb);
	void *addr = (void *)((u64)AEON_SB(sb)->virt_addr + base_addr);

	memset(addr, 0, 4096);
	managed_memory_start = last_valid_address = addr;
	last_valid_address = addr + (1 << AEON_SHIFT) - 1;
	mcb = (struct mem_control_block *)addr;
	mcb->size = 256;
	mcb->is_used = 0;

	has_initialized = 1;
}

void *pmem_malloc(struct super_block *sb, long bytes)
{
	struct mem_control_block *mcb;
	void *current_location;
	void *memory_location;

	if (!has_initialized)
		malloc_init(sb);

alloc:
	bytes = bytes + sizeof(struct mem_control_block);
	current_location = managed_memory_start;
	memory_location = 0;

	while (current_location <= last_valid_address) {
		mcb = (struct mem_control_block *)current_location;
		mcb->size = 256;
		if (!mcb->is_used && mcb->size >= bytes &&
		    current_location + bytes <= last_valid_address) {
			mcb->is_used = 1;
			memory_location = current_location;
			break;
		}
		current_location += mcb->size;
	}

	if (!memory_location) {
		u64 base_addr = aeon_get_new_blk(sb);
		void *addr = (void *)((u64)AEON_SB(sb)->virt_addr + base_addr);

		managed_memory_start = addr;
		last_valid_address = addr + (1 << AEON_SHIFT) -1 ;

		memset(addr, 0, 4096);
		mcb = (struct mem_control_block *)addr;
		mcb->is_used = 0;
		mcb->size = 256;

		goto alloc;
	}

	memory_location += sizeof(struct mem_control_block);
	aeon_dbg("0x%llx", (u64)memory_location);

	return memory_location;
}

void pmem_free(void *head)
{
	struct mem_control_block *mcb;
	mcb = head - sizeof(struct mem_control_block);
	mcb->is_used = 0;
}

void pmem_create_pool(struct super_block *sb)
{
}
