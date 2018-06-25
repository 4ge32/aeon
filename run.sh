#!/bin/sh

FS="aeon"
DEV=/dev/pmem0
MOUNT_POINT=mnt

run () {
  sudo umount $MOUNT_POINT
  sudo rmmod $FS
  make
  sync
  sudo insmod $FS.ko
  sudo mount -t $FS -o init $DEV $MOUNT_POINT
  dmesg > err.log
}

rrun() {
  sudo umount $MOUNT_POINT
  sudo mount -t $FS $DEV $MOUNT_POINT
  dmesg > err.log
}

clean () {
  sudo umount $MOUNT_POINT
  sudo rmmod $FS
  make clean
}

fs_test() {
	echo $FS
}

case "$1" in
  clean)
    clean
    ;;
  test)
    fs_test
    ;;
  rt)
    rrun
    ;;
  *)
    run
    ;;
esac
exit 0
