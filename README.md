# AEON: A file system designed for NVMM
AEON is a file system designed for Non-volatile main memory (NVMM) with scalability in mind.

AEON maps the entire NVMM region to a kernel virtual address space to enhance performance.
AEON protects the mapped address space with write windows scheme when the option is enabled.

Blocks allocation of AEON is fast and scalable. 
AEON has multiple allocation groups as same as the number of CPU cores and allocates blocks with a hint from running CPU to enhance allocation efficiency.

Inode allocation of AEON is also fast and scalable. AEON has inode caches as same as the number of CPU cores.
AEON allocates a region for new inode from a cache which chooses from a running CPU and released inodes connect the corresponding inode cache. 
When released inodes region is existing, AEON reuses it preferentially with the temporal locality in mind. This mind applies for the other meta-data allocation.

AEON updates all data in-place for performance.
AEON updates meta-data with mutual pointer protection to enhance high performance with atomicity.

**Not this feature merged to master fully.** 
AEON can handle NUMA NVDIMM architecture efficiently to map each NUMA node to a kernel virtual address space separately.
AEON switches the mapped head address per NUMA node to use each NUMA node. 
Thanks to this design, AEON exploits the NUMA NVDIMM architecture and can scale under the heavy concurrent situation.
The experimental code is [here](https://github.com/4ge32/aeon-gevanni).

### COMPRESSION MODE
AEON is equipped with compression mode by the zstd library (Not stable).

## Supported Linux kernel version
Linux kernel 4.19.4 or higher

## Building and Using AEON
You can set up the environment of with NVMMs and try it even if you don't have real devices.
To set up the environment,  [this site](https://nvdimm.wiki.kernel.org/) can be helpful.

The basic mount flow is following:
```bash
make -j
insmod aeon.ko
mount -t aeon -o dax $DEV $MNT
```
When first mounting, the `init` option is needed for initialization. AEON doesn't have an appropriate `mkfs`command so far.

## Hacking and Contirubuting
If you find bugs, please [report them](httpfs://github.com/4ge32/aeon/issues).

If you have other questions or suggestions, you contact me at [shfy1014[at]google.com](mailto:shfy1014[at]google.com).
