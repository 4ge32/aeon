DIR=/mnt
TMP=/tmp/aeon_test

source ./makeManyfile.sh

init () {
  mkdir $TMP 1>/dev/null
}

clean () {
  rm -r $TMP 1>/dev/null
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

  cat article-1 > $TMP/art
  cat article-1 > $DIR/art
  diff $TMP $DIR
  res=$?
  clean
}

test-write-3 ()
{
  init

  cat article-2 > $TMP/art
  cat article-2 > $DIR/art
  diff $TMP $DIR
  res=$?
  clean
}

helper_recover_test ()
{
  if [ ! -e attack_metadata ]; then
    gcc -o attack_metadata attack_metadata.c
  fi

  for i in $OBJ
  do
    touch $DIR/$i
  done
  for i in $RES
  do
    touch $TMP/$i
  done
  ./attack_metadata $1 $2 $DIR/$TARGET
  ./run.sh rm
  diff $TMP $DIR
  res=$?
}

test-recover-1 ()
{
  init

  # Only success under the num of 4 CPU cores.
  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm R-5 dram pmem"

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
  RES="nvdimm dark dram pmem"

  helper_recover_test 3 7

  clean
}

test-recover-9 ()
{
  init

  TARGET="dark"
  OBJ="nvdimm dark dram pmem"
  RES="nvdimm R-5 dram pmem"

  helper_recover_test 3 8

  clean
}
