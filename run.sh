#!/bin/sh

FS="aeon"
DEV=/dev/pmem0
MOUNT_POINT=/mnt

run () {
  sudo insmod $FS.ko
  sudo mount -t $FS -o init $DEV $MOUNT_POINT
}

rrun() {
  sudo umount $MOUNT_POINT
  sudo mount -t $FS $DEV $MOUNT_POINT
}

clean () {
  sudo umount $MOUNT_POINT
  sudo rmmod $FS
  #make clean
}

nvdimm_set () {
   sudo ndctl create-namespace -e "namespace0.0" -m memory -f
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
  rm)
    rrun
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
