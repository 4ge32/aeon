#!/bin/sh

. ./env_mini_performance_test

init () {
  sudo ndctl create-namespace -e "namespace0.0" -m memory -f > /dev/null

  case $NAME in
  "ext2" | "ext4")
    yes | sudo mkfs.$NAME /dev/pmem0 > /dev/null 2>&1
    sudo mount -o dax /dev/pmem0 $MNT
    ;;
  "ext4_writeback")
    yes | sudo mkfs.$NAME /dev/pmem0 > /dev/null 2>&1
    sudo mount -o dax,data=writeback /dev/pmem0 $MNT
    ;;
  "xfs" )
    sudo mkfs.$NAME /dev/pmem0 > /dev/null 2>&1
    sudo mount -o dax /dev/pmem0 $MNT
    ;;
  "nova")
    sudo insmod nova.ko
    sudo mount -t NOVA -o init,dax /dev/pmem0 $MNT
    ;;
  "aeon")
    sudo insmod aeon.ko
    sudo mount -t aeon -o init,dax /dev/pmem0 $MNT
    ;;
  *)
    echo "?"
    ;;
  esac
}

clean () {
  sudo umount $MNT
  case $NAME in
  "nova" | "aeon")
    sudo rmmod ${NAME}
    ;;
  esac
}

create() {
  . ./env_mini_performance_test
  for dir in $DIR
  do
    mkdir $MNT/$dir
    for i in `seq 1 $N`
    do
      touch $MNT/$dir/$i
    done
  done
}

remove () {
  . ./env_mini_performance_test
  for dir in $DIR
  do
    rm -r $MNT/$dir
  done
}

run () {
  for j in `seq 1 $C`
  do
    init
    export -f create
    echo "create" | /usr/bin/time -f %S /bin/bash 2>> $TMP/${NAME}_create.txt 1>/dev/null
    export -f remove
    echo 'remove' | (/usr/bin/time -f %S /bin/bash) 2>> $TMP/${NAME}_remove.txt 1>/dev/null
    clean
  done
  cat $TMP/${NAME}_create.txt
  echo -n "CREATE: "
  cat $TMP/${NAME}_create.txt | awk '{sum+=$1} END{print sum/NR}'
  cat $TMP/${NAME}_remove.txt
  echo -n "REMOVE: "
  cat $TMP/${NAME}_remove.txt | awk '{sum+=$1} END{print sum/NR}'
  rm $TMP/${NAME}_create.txt
  rm $TMP/${NAME}_remove.txt
}

can () {
  init
  export -f create
  echo "create" | /usr/bin/time -p /bin/bash 2>> $TMP/${NAME}_create.txt 1>/dev/null
  clean
  cat $TMP/${NAME}_create.txt
}

#echo "Ext2"
#NAME="ext2"
#run
#
#echo "Ext4"
#NAME="ext4"
#run
#
#echo "Ext4 (no journal)"
#NAME="ext4_writeback"
#run
#
#echo "Xfs"
#NAME="xfs"
#run
#
echo "NOVA"
NAME="nova"
run

#echo "AEON"
#NAME="aeon"
#run
