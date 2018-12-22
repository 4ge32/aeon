#
# Makefile for the linux filesystem.
#

CONFIG_AEON_FS_XATTR=y
CONFIG_AEON_FS_SECURITY=y
CONFIG_AEON_FS_COMPRESSION=y
CONFIG_AEON_FS_DEBUG_MODE=y

ifdef CONFIG_AEON_FS_XATTR
ccflags-y += -DCONFIG_AEON_FS_XATTR
endif

ifdef CONFIG_AEON_FS_SECURITY
ccflags-y += -DCONFIG_AEON_FS_SECURITY
endif

ifdef CONFIG_AEON_FS_COMPRESSION
ccflags-y += -DCONFIG_AEON_FS_COMPRESSION
endif

ifdef CONFIG_AEON_FS_DEBUG_MODE
ccflags-y += -DCONFIG_AEON_FS_DEBUG_MODE
endif

ccflags-y += -I$(src)/libaeon

obj-m += aeon.o

aeon-y += 	$(addprefix libaeon/, \
		malloc.o \
		tree.o \
		libtest.o \
		)

aeon-y += super.o balloc.o inode.o mprotect.o namei.o dir.o  \
	file.o extents.o rebuild.o symlink.o debug.o ioctl.o \

aeon-$(CONFIG_AEON_FS_XATTR) += xattr.o xattr_user.o xattr_trusted.o
aeon-$(CONFIG_AEON_FS_SECURITY) += xattr_security.o
aeon-$(CONFIG_AEON_FS_COMPRESSION) += compression.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean
