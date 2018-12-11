#/bin/sh

OK ()
{
  echo -e "\t [OK]"
}

FAILED ()
{
  echo -e "\t [FAILED]"
}

_do_test ()
{
  S=$1
  N=$2
  for num in `seq $S $N`
  do
    res=1
    ./run.sh
    echo -n "test-$3-$num"
    test-$3-$num
    if [ "$res" = "0" ]; then
      OK
    else
      FAILED
    fi
    ./run.sh clean
  done
}

rename ()
{
  N=5
  for num in `seq 1 $N`
  do
    res=1
    ./run.sh
    echo -n "test-rename-$num"
    test-rename-$num
    if [ "$res" = "0" ]; then
      OK
    else
      FAILED
    fi
    ./run.sh clean
  done
}

remove ()
{
  N=4
  for num in `seq 1 $N`
  do
    res=1
    ./run.sh
    echo -n "test-remove-$num"
    test-remove-$num
    if [ "$res" = "0" ]; then
      OK
    else
      FAILED
    fi
    ./run.sh clean
  done
}

create ()
{
  N=4
  for num in `seq 1 $N`
  do
    res=1
    ./run.sh
    echo -n "test-create-$num"
    test-create-$num
    if [ "$res" = "0" ]; then
      OK
    else
      FAILED
    fi
    ./run.sh clean
  done
}

hard_and_sym_link ()
{
  N=3
  for num in `seq 2 $N`
  do
    res=1
    ./run.sh
    echo -n "test-link-$num"
    test-link-$num
    if [ "$res" = "0" ]; then
      OK
    else
      FAILED
    fi
    ./run.sh clean
  done
}

attr ()
{
  N=4
  for num in `seq 1 $N`
  do
    res=1
    ./run.sh
    echo -n "test-attr-$num"
    test-attr-$num
    if [ "$res" = "0" ]; then
      OK
    else
      FAILED
    fi
    ./run.sh clean
  done
}

mmap ()
{
  N=1
  for num in `seq 1 $N`
  do
    res=1
    ./run.sh
    echo -n "test-mmap-$num"
    test-mmap-$num
    if [ "$res" = "0" ]; then
      OK
    else
      FAILED
    fi
    ./run.sh clean
  done
}

write ()
{
  _do_test 1 2 write
}

recover ()
{
  _do_test 1 15 recover
}

libaeon ()
{
  _do_test 1 1 libaeon
}

compression ()
{
  _do_test 1 1 compression
}

other ()
{
  _do_test 1 2 other
}

source ./list_test.sh
echo "===== TEST START ====="

case "$1" in
  rename)
    rename
    ;;
  remove)
    remove
    ;;
  create)
    create
    ;;
  link)
    hard_and_sym_link
    ;;
  attr)
    attr
    ;;
  mmap)
    mmap
    ;;
  write)
    write
    ;;
  recover)
    recover
    ;;
  libaeon)
    libaeon
    ;;
  compression)
    compression
    ;;
  other)
    other
    ;;
  all)
    mmap
    write
    attr
    hard_and_sym_link
    remove
    rename
    create
    recover
    other
    ;;
  *)
    echo "remoe rename create all"
    ;;
esac
echo "===== TEST FINISH ====="

exit 0
