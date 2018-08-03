DEST=/mnt

empty_file() {
  NAME=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 6 | head -n 1 | sort | uniq`
}

asize_file() {
  for i in `seq 1 $NUM`:
  do
    NAME=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 6 | head -n 1 | sort | uniq`
    dd if=/dev/urandom of=$DEST/$NAME.dat count=1024 bs=1K
  done
}

case "$1" in
  empty)
    empty_file
    ;;
  no-empty)
    asize_file
    ;;
   *)
     ;;
esac
