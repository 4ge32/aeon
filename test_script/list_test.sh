DIR=/mnt
TMP=/tmp/aeon_test
TEST_AEON=aeonfstest

source ./makeManyfile.sh

init () {
  mkdir $TMP 1>/dev/null
}

clean () {
  rm -r $TMP 1>/dev/null
  if [ -e $TEST_AEON ]; then
    rm $TEST_AEON
  fi
}

# directory operations
test-rename-1 ()
{
  init

  for i in $DIR $TMP
  do
    touch $i/good
    mkdir $i/dir
    mv $i/good $i/dir/
  done
  diff -r $TMP $DIR
  res=$?

  clean
}

test-rename-2 ()
{
  init

  for i in $DIR $TMP
  do
    touch $i/good
    mkdir $i/dir
    mv $i/good $i/dir
  done
  diff -r $TMP $DIR
  res=$?

  clean
}

test-rename-3 ()
{
  init

  for i in $DIR $TMP
  do
    touch $i/good
    mv $i/good $i/bad
  done
  diff -r $TMP $DIR
  res=$?

  clean
}

test-rename-4 ()
{
  touch $DIR/good
  mkdir  $DIR/dir
  mv $DIR/dir $DIR/good > /dev/null 2>&1

  if [ $? -eq 1 ]; then
    res=0
  fi
}

test-rename-5 ()
{
  init

  for i in $DIR $TMP
  do
    mkdir $i/dir
    mv $i/dir $i/newdir
  done
  diff -r $TMP $DIR
  res=$?

  clean
}

test-rename-6 ()
{
  init

  mkdir $DIR/test
  mkdir $DIR/next
  mkdir -p $TMP/test/next
  mv $DIR/next $DIR/test
  ./run.sh rm
  diff -r $TMP $DIR
  res=$?

  clean
}

test-create-1 ()
{
  init

  NUM=32
  for i in `seq 1 $NUM`
  do
    empty_file
    touch $DIR/$NAME
    touch $TMP/$NAME
  done
  diff -r $TMP $DIR
  res=$?

  clean
}

test-create-2 ()
{
  init

  NUM=300
  for i in `seq 1 $NUM`
  do
    empty_file
    touch $DIR/$NAME
    touch $TMP/$NAME
  done
  diff -r $TMP $DIR
  res=$?

  clean
}

test-create-3 ()
{
  init

  NUM=62
  for i in `seq 1 $NUM`
  do
    empty_file
    touch $DIR/$NAME
    touch $TMP/$NAME
  done
  ./run.sh rm
  diff -r $TMP $DIR
  res=$?

  clean
}

test-create-4 ()
{
  init

  NUM=300
  for i in `seq 1 $NUM`
  do
    empty_file
    touch $DIR/$NAME
    touch $TMP/$NAME
  done
  ./run.sh rm
  diff -r $TMP $DIR
  res=$?

  clean
}

test-create-5 ()
{
  init

  NR="one two three four five"

  NUM=4000
  for dir in $NR
  do
    mkdir $DIR/$dir
    mkdir $TMP/$dir
    for i in `seq 1 $NUM`
    do
      empty_file
      touch $DIR/$dir/$NAME
      touch $TMP/$dir/$NAME
    done
  done
  diff -r $TMP $DIR
  res=$?

  clean
}


test-create-6 ()
{
  init

  NUM=4096
  for i in `seq 1 $NUM`
  do
    empty_file
    touch $DIR/$NAME
    touch $TMP/$NAME
  done
  diff -r $TMP $DIR
  res=$?

  clean
}

test-create-7 ()
{
  init

  NUM=8000
  for i in `seq 1 $NUM`
  do
    empty_file
    touch $DIR/$NAME
    touch $TMP/$NAME
  done
  diff -r $TMP $DIR
  res=$?

  clean
}

test-remove-1 ()
{
  init

  DELETE=$((RANDOM%+10 + 1))
  D_FILE=""
  NUM=10
  for i in `seq 1 $NUM`
  do
    empty_file
    touch $DIR/$NAME
    touch $TMP/$NAME
    if [ $i -eq $DELETE ]; then
      D_FILE=$NAME
    fi
  done
  rm $DIR/$D_FILE
  rm $TMP/$D_FILE
  diff -r $TMP $DIR
  res=$?

  clean
}

test-remove-2 ()
{
  init

  mkdir $DIR/newdir
  mkdir $TMP/newdir
  rmdir $DIR/newdir
  rmdir $TMP/newdir
  diff -r $TMP $DIR
  res=$?

  clean
}

test-remove-3 ()
{
  init

  DELETE=$((RANDOM%+10 + 1))
  D_FILE=""
  NUM=10
  for i in `seq 1 $NUM`
  do
    empty_file
    touch $DIR/$NAME
    touch $TMP/$NAME
    if [ $i -eq $DELETE ]; then
      D_FILE=$NAME
    fi
  done
  rm $DIR/$D_FILE
  rm $TMP/$D_FILE
  for i in `seq 1 2`
  do
    empty_file
    touch $DIR/$NAME
    touch $TMP/$NAME
  done
  diff -r $TMP $DIR
  res=$?

  clean
}

test-remove-4 ()
{
  init

  touch $DIR/hello
  touch $TMP/hello
  touch $DIR/world
  touch $TMP/world
  rm $DIR/hello
  rm $TMP/hello
  touch $DIR/uber
  touch $TMP/uber
  diff <(ls -l $DIR) <(ls -l $TMP)
  res=$?

  clean
}

test-link-1 ()
{
  init

  echo "hello" > $DIR/file1.txt
  echo "hello" > $TMP/file1.txt
  echo "world" > $DIR/file2.txt
  echo "world" > $TMP/file2.txt
  ln $DIR/file1.txt $DIR/file3.txt
  ln $TMP/file1.txt $TMP/file3.txt
  diff <(ls -l $DIR) <(ls -l $TMP)
  res=$?

  clean
}

test-link-2 ()
{
  init

  echo "hello" >> $DIR/file1.txt
  echo "hello" >> $TMP/file1.txt
  ln -s $DIR/file1.txt $DIR/file2.txt
  ln -s $TMP/file1.txt $TMP/file2.txt
  diff $DIR/file2.txt $TMP/file2.txt
  res=$?

  clean
}

test-link-3 ()
{
  init

  echo "hello" >> $DIR/file1.txt
  echo "world" >> $TMP/file1.txt
  ln -s $DIR/file1.txt $TMP/file2.txt
  ln -s $TMP/file1.txt $DIR/file2.txt
  diff $DIR/file2.txt $TMP/file1.txt
  diff $DIR/file1.txt $TMP/file2.txt
  res=$?

  clean
}

test-attr-1 ()
{
  init

  empty_file
  touch $DIR/$NAME
  touch $TMP/$NAME
  sudo chown root $DIR/$NAME
  sudo chown root $TMP/$NAME
  diff <(ls -l $DIR | awk '{print $3}') <(ls -l $TMP | awk '{print $3}')
  res=$?

  clean
}

test-attr-2 ()
{
  init

  empty_file
  touch $DIR/$NAME
  touch $TMP/$NAME
  sudo chmod 777 $DIR/$NAME
  sudo chmod 777 $TMP/$NAME
  diff <(ls -l $DIR | awk '{print $1}') <(ls -l $TMP | awk '{print $1}')
  res=$?

  clean
}

test-attr-3 ()
{
  init

  empty_file
  touch $DIR/$NAME
  touch $TMP/$NAME
  sudo chown root $DIR/$NAME
  sudo chown root $TMP/$NAME
  ./run.sh rm
  diff <(ls -l $DIR | awk '{print $3}') <(ls -l $TMP | awk '{print $3}')
  res=$?

  clean
}


test-attr-4 ()
{
  init

  empty_file
  touch $DIR/$NAME
  touch $TMP/$NAME
  sudo chmod 777 $DIR/$NAME
  sudo chmod 777 $TMP/$NAME
  ./run.sh rm
  diff <(ls -l $DIR | awk '{print $1}') <(ls -l $TMP | awk '{print $1}')
  res=$?

  clean
}

test-mmap-1 ()
{
  cp hello.c $DIR/hello.c
  gcc $DIR/hello.c -o $DIR/a.out
  path=`pwd`
  cd $DIR
  res=`./a.out`
  test "$res" = "Hello, World"
  res=$?
  cd $path
}

test-write-1 ()
{
  init

  path=`pwd`
  cp hello.c $DIR/hello.c
  cp hello.c $TMP/hello.c
  cd $DIR
  gcc hello.c
  cd $TMP
  gcc hello.c
  cmp -s $DIR/a.out $TMP/a.out
  cd $path
  res=$?

  clean
}

test-write-2 ()
{
  init

  FILE=list_test.sh
  TARGET=target
  cp $FILE $DIR/
  cp $FILE $TMP/
  touch $DIR/$TARGET
  touch $TMP/$TARGET
  for i in `seq 1 10`
  do
    cat $DIR/$FILE $DIR/$FILE >> $DIR/$TARGET
    cat $TMP/$FILE $TMP/$FILE >> $TMP/$TARGET
  done
  ./run.sh rm
  diff $DIR/$TARGET $TMP/$TARGET
  res=$?

  clean
}

helper_recover_test ()
{
  if [ ! -e $TEST_AEON ]; then
    gcc -o $TEST_AEON ${TEST_AEON}.c
  fi

  for i in $OBJ
  do
    touch $DIR/$i
  done
  for i in $RES
  do
    touch $TMP/$i
  done
  ./$TEST_AEON $1 $2 $DIR/$TARGET
  ./run.sh rm
  diff $TMP $DIR
  res=$?
}

helper_recover_test_im ()
{
  if [ ! -e $TEST_AEON ]; then
    gcc -o $TEST_AEON ${TEST_AEON}.c
  fi

  for i in $OBJ
  do
    touch $DIR/$i
  done
  for i in $RES
  do
    touch $TMP/$i
  done
  ./$TEST_AEON $1 $2 $DIR/$TARGET
  ./run.sh rm
  #ls $DIR
  touch $TMP/MARS
  touch $DIR/MARS
  #ls $TMP
  #ls $DIR
  diff $TMP $DIR
  res=$?
}

test-recover-1 ()
{
  init

  # Only success under the num of 16 CPU cores.
  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm R-17 dram pmem"

  helper_recover_test 1 1

  clean
}

test-recover-2 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dram pmem"

  helper_recover_test 2 1

  clean
}

test-recover-3 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dram pmem"

  helper_recover_test 2 2

  clean
}

test-recover-4 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dram pmem"

  helper_recover_test 2 3

  clean
}

test-recover-5 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES=$OBJ

  helper_recover_test 2 4

  clean
}

test-recover-6 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES=$OBJ

  helper_recover_test 3 5

  clean
}

test-recover-7 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dram pmem"

  helper_recover_test 3 6

  clean
}

test-recover-8 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm R-17 dram pmem"

  helper_recover_test 3 7

  clean
}

test-recover-9 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dark dram pmem"

  helper_recover_test 3 8

  clean
}

test-recover-10 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dark dram pmem"

  helper_recover_test_im 3 8

  clean
}

test-recover-11 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dark dram pmem"

  helper_recover_test 3 9

  clean
}

test-recover-12 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dark dram pmem"

  helper_recover_test_im 3 9

  clean
}

test-recover-13 ()
{
  init

  a=3
  b=10
  TARGET="dram"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dram pmem"

  if [ ! -e $TEST_AEON ]; then
    gcc -o $TEST_AEON ${TEST_AEON}.c
  fi

  for i in $OBJ
  do
    touch $DIR/$i
  done
  for i in $RES
  do
    touch $TMP/$i
  done
  rm $DIR/dark
  ./$TEST_AEON $a $b $DIR/$TARGET
  ./run.sh rm
  diff $TMP $DIR
  res=$?

  clean
}

test-recover-14 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dram pmem"

  helper_recover_test_im 3 11

  clean
}

test-recover-15 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm R-17 dram pmem"

  helper_recover_test_im 3 12

  clean
}

test-recover-16 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm R-17 dram pmem"

  helper_recover_test_im 3 13

  clean
}

test-recover-17 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dram pmem"

  helper_recover_test_im 3 14

  clean
}

test-recover-18 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dark dram pmem"

  helper_recover_test_im 3 15

  clean
}

test-recover-19 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm R-17 dram pmem"

  helper_recover_test_im 3 16

  clean
}

test-recover-20 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dram pmem"

  helper_recover_test_im 3 17

  clean
}

test-recover-21 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dark dram pmem"

  helper_recover_test_im 3 18

  clean
}

test-recover-22 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dark dram pmem"

  helper_recover_test_im 3 19

  clean
}

test-recover-23 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm dark dram pmem"

  helper_recover_test_im 3 20

  clean
}

test-recover-24 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm R-17 dram pmem"

  helper_recover_test_im 3 21

  clean
}

do_fake_rename ()
{
  init

  # fake rename
  touch $DIR/orig
  if [ $# -eq 1 ]; then
    touch $DIR/target
  fi

  touch $TMP/target

  if [ ! -e $TEST_AEON ]; then
    gcc -o $TEST_AEON ${TEST_AEON}.c
  fi

  ./$TEST_AEON 3 $1 $DIR/orig

  ./run.sh rm

  for i in `seq 1 30`
  do
    touch $DIR/NEW$i
    touch $TMP/NEW$i
  done

  #ls $DIR
  #cd ..
  #./run.sh dentry
  diff -r $DIR $TMP
  res=$?

  clean
}

test-recover-25 ()
{
  do_fake_rename 22
}

helper_recover_test_delete ()
{
  init

  if [ ! -e $TEST_AEON ]; then
    gcc -o $TEST_AEON ${TEST_AEON}.c
  fi

  n=30
  nplus=$(($n+1))
  N=50

  mkdir $DIR/dirtest
  mkdir $TMP/dirtest

  for i in `seq 1 $N`
  do
    touch $DIR/dirtest/OLD$i
  done

  for i in `seq 1 $n`
  do
    touch $TMP/dirtest/OLD$i
  done

  for i in `seq $nplus $N`
  do
    ./$TEST_AEON $1 $2 $DIR/dirtest/OLD$i
  done

  #echo "direntry"
  #echo "TMP"
  #ls $TMP/dirtest
  #echo "DIR"
  #ls $DIR/dirtest

  #for i in `seq 18 $N `
  #do
  #  ./$TEST_AEON $1 $2 $DIR/dirtest/OLD$i
  #done
  ./run.sh rm

  # confirm whether region is overwritten or not
  for i in `seq 1 $N`
  do
    touch $TMP/dirtest/NEW$i
    touch $DIR/dirtest/NEW$i
  done
  #echo "FINAL"
  #echo "TMP"
  #ls $TMP/dirtest
  #echo "DIR"
  #ls $DIR/dirtest

  diff -r $TMP $DIR
  res=$?

  clean
}

helper_recover_test_replace ()
{
  init

  if [ ! -e $TEST_AEON ]; then
    gcc -o $TEST_AEON ${TEST_AEON}.c
  fi

  # config which depends num cpu
  # discard the newer dentry table
  n=30
  nplus=$(($n+1))
  N=50
  Nminus=$(($N-4))
  num_inode=47

  mkdir $DIR/dirtest
  mkdir $TMP/dirtest

  # initial state
  for i in `seq 1 $N`
  do
    touch $DIR/dirtest/OLD$i
  done

  # prepare the expected state
  for i in `seq 1 $n`
  do
    touch $TMP/dirtest/OLD$i
  done
  for _i in `seq $nplus $Nminus`
  do
    touch $TMP/dirtest/R-$num_inode
    num_inode=$(($num_inode+1))
  done

    # destroy
  for i in `seq $nplus $N`
  do
    ./$TEST_AEON $1 $2 $DIR/dirtest/OLD$i
  done

  ./run.sh rm

  # confirm whether region is overwritten or not
  for i in `seq 1 $N`
  do
    touch $TMP/dirtest/NEW$i
    touch $DIR/dirtest/NEW$i
  done

  diff -r $TMP $DIR
  res=$?

  clean
}

helper_recover_test_remain ()
{
  init

  if [ ! -e $TEST_AEON ]; then
    gcc -o $TEST_AEON ${TEST_AEON}.c
  fi

  # config which depends num cpu
  # discard the newer dentry table
  n=30
  nplus=$(($n+1))
  N=50

  mkdir $DIR/dirtest
  mkdir $TMP/dirtest

  # initial state
  for i in `seq 1 $N`
  do
    touch $DIR/dirtest/OLD$i
  done

  # prepare the expected state
  for i in `seq 1 $N`
  do
    touch $TMP/dirtest/OLD$i
  done

    # destroy
  for i in `seq $nplus $N`
  do
    ./$TEST_AEON $1 $2 $DIR/dirtest/OLD$i
  done

  ./run.sh rm

  # confirm whether region is overwritten or not
  for i in `seq 1 $N`
  do
    touch $TMP/dirtest/NEW$i
    touch $DIR/dirtest/NEW$i
  done

  diff -r $TMP $DIR
  res=$?

  clean
}

# more load
test-recover-26 ()
{
  helper_recover_test_delete 3 11
}

test-recover-27 ()
{
  helper_recover_test_replace 3 12
}

test-recover-28 ()
{
  helper_recover_test_replace 3 13
}

test-recover-29 ()
{
  helper_recover_test_delete 3 14
}

test-recover-30 ()
{
  helper_recover_test_remain 3 15
}

test-recover-31 ()
{
  helper_recover_test_replace 3 16
}

test-recover-32 ()
{
  helper_recover_test_delete 3 17
}

test-libaeon-1 ()
{
  init

  if [ ! -e $TEST_AEON ]; then
    gcc -o $TEST_AEON ${TEST_AEON}.c
  fi

  touch $DIR/fake
  ./$TEST_AEON 4 1 $DIR/fake
  res=$?

  clean
}

test-compression-1 ()
{
  init

  if [ ! -e $TEST_AEON ]; then
    gcc -o $TEST_AEON ${TEST_AEON}.c
  fi

  touch $DIR/fake
  ./$TEST_AEON 5 1 $DIR/fake
  res=$?

  clean
}

test-other-1 ()
{
  init

  touch $DIR/abc
  touch $DIR/bcd
  touch $TMP/good
  touch $TMP/bcd
  rm $DIR/abc
  ./run.sh rm
  touch $DIR/good
  diff $TMP $DIR
  res=$?

  clean
}

test-other-2 ()
{
  init

  for i in `seq 1 100`
  do
    touch $DIR/$i
    touch $TMP/$i
  done
  for i in `seq 4 6`
  do
    rm $DIR/$i
    rm $TMP/$i
  done
  for i in `seq 40 57`
  do
    rm $DIR/$i
    rm $TMP/$i
  done
  for i in `seq 78 94`
  do
    rm $DIR/$i
    rm $TMP/$i
  done
  ./run.sh rm
  for i in `seq 1 30`
  do
    touch $DIR/NEW$i
    touch $TMP/NEW$i
  done
  diff $TMP $DIR
  res=$?

  clean
}

# check the state of direntry
test-other-3 ()
{
  init

  touch /mnt/abc
  touch /mnt/bcd
  ./run.sh rm
  touch /mnt/f
  touch /mnt/ff
  touch /mnt/fff

  cd ..
  ret=`./run.sh dentry`
  res=0
  if [[ $ret == *"?"* ]]; then
    res=1
  fi

  clean
}
