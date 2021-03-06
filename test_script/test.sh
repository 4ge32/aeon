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
    echo -n "test-${FUNCNAME[1]}-$num"
    test-${FUNCNAME[1]}-$num
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
  _do_test 1 6
}

remove ()
{
  _do_test 1 4
}

create ()
{
  _do_test 1 4
}

link ()
{
  _do_test 1 3
}

attr ()
{
  _do_test 1 4
}

mmap ()
{
  _do_test 1 1
}

write ()
{
  _do_test 1 3
}

recover ()
{
  _do_test 1 32
}

libaeon ()
{
  _do_test 1 1
}

compression ()
{
  OPT="CONFIG_AEON_FS_COMPRESSION"
  cat ../Makefile | grep \#${OPT} >> /dev/null
  if [ $? -eq 0 ]; then
    echo "Enable $OPT"
  fi
  _do_test 1 5
}

other ()
{
  _do_test 1 4
}

source ./list_test.sh
echo "===== TEST START ====="

OPT=CONFIG_AEON_FS_PERCPU_INODEMAP
cat ../Makefile | grep \#${OPT} >> /dev/null
if [ $? -eq 1 ]; then
  echo "Disable $OPT"
  exit 1
fi

./run.sh set > /dev/null 2>&1

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
    link
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
  compression)
    compression
    ;;
  all)
    mmap
    write
    attr
    link
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
