#
# Makefile for the linux filesystem.
#

obj-m += aeon.o

aeon-y := super.o balloc.o inode.o mprotect.o namei.o dir.o file.o rebuild.o symlink.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean
