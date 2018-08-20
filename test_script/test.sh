#/bin/sh

OK ()
{
  echo " [OK]"
}

FAILED ()
{
  echo " [FAILED]"
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
  N=3
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
  N=2
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
  all)
    attr
    hard_and_sym_link
    remove
    rename
    #create
    ;;
  *)
    echo "remoe rename create all"
    ;;
esac
echo "===== TEST FINISH ====="

exit 0
