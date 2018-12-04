#include <linux/zstd.h>

#include "aeon.h"

void try_api(void)
{
	ZSTD_parameters params = ZSTD_getParams(1, 4096, 0);
}
