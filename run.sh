#!/bin/sh

FS="aeon"
DEV=/dev/pmem0
DEV2=/dev/pmem1
MOUNT_POINT=/mnt
OPT=init,dax,wprotect,user_xattr
R_OPT=dax,wprotect,user_xattr

run () {
  sudo insmod $FS.ko
  sudo mount -t $FS -o $OPT $DEV $MOUNT_POINT
}

remount_run() {
  # Now actual remount is not supported.
  sudo umount $MOUNT_POINT
  sudo mount -t $FS -o $R_OPT $DEV $MOUNT_POINT
}

xfs () {
  sudo rmmod $FS
  nvdimm_set
  nvdimm_set2
  sudo insmod $FS.ko
  sudo mount -t $FS -o $OPT $DEV $MOUNT_POINT
  sudo umount $MOUNT_POINT
  sudo mount -t $FS -o $OPT $DEV2 $MOUNT_POINT
  sudo umount $MOUNT_POINT
}

debug_run () {
  sudo insmod $FS.ko
  sudo mount -t $FS -o init,dax,dbgmask=16 $DEV $MOUNT_POINT
}

debug_remount_run() {
  sudo umount $MOUNT_POINT
  sudo mount -t $FS -o dax,dbgmask=16 $DEV $MOUNT_POINT
}

clean () {
  sudo umount $MOUNT_POINT
  sudo rmmod $FS
  #make clean
}

nvdimm_set () {
   sudo ndctl create-namespace -e "namespace0.0" -m memory -f
}

nvdimm_set2 () {
   sudo ndctl create-namespace -e "namespace1.0" -m memory -f
}

show_info () {
  sudo cat /sys/kernel/debug/aeon/free_list
}

show_imem_info () {
  sudo cat /sys/kernel/debug/aeon/imem_cache
}

show_dentries_info () {
  sudo cat /sys/kernel/debug/aeon/dentries
}

case "$1" in
  clean)
    clean
    ;;
  set)
    nvdimm_set
    ;;
  xfs)
    xfs
    ;;
  rm)
    remount_run
    ;;
  debug)
    debug_run
    ;;
  drm)
    debug_remount_run
    ;;
  info)
    show_info
    ;;
  imem)
    show_imem_info
    ;;
  dentry)
    show_dentries_info
    ;;
  *)
    run
    ;;
esac
exit 0
