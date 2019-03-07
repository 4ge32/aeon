/*
 * New Extents support for AEON
 * ON THE WAY
 *
 * Design Overview
 *
 * Address           Address           Address           Address
 * #1                #100              #500              #800
 *
 * |----------|      |----------|      |----------|      |----------|
 * |--header--|  |-->|--header--|  |-->|--header--|  |-->|          |
 * | height 2 |  |   | height 1 |  |   | height 0 |  |   |          |
 * |----------|  |   |----------|  |   |----------|  |   |          |
 * |---idx1---|  |   |---idx1---|  |   |--extent--|  |   |          |
 * | offset 0 |--|   | offset 0 |--|   | offset 0 |--|   |----------|
 * | addr 100 |      | addr 500 |      | len    2 |
 * |----------|      |----------|      | addr 800 |      Address
 * |   ...    |      |---idx2---|      |----------|      #900
 * |          |      | offset 9 |      |--extent--|
 * |          |      | addr 600 |      | offset 2 |--|   |----------|
 * |----------|      |----------|      | len    1 |  |-->|          |
 *                   |   ...    |      | addr 900 |      |          |
 *                   |          |      |----------|      |----------|
 *                   |----------|      |   ...    |
 *                                     |----------|
 *
 * Enable to handle about 16TiB regions by above management.
 * - Max height 3
 * - 254 idxs per 4k block
 * - 254 extents per 4k block
 */
#include <linux/fs.h>

#include "aeon.h"
#include "aeon_super.h"
#include "aeon_extents.h"
#include "aeon_balloc.h"
