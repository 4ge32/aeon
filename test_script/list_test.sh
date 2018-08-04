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

test-create-2 ()
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

  DELETE=$((RANDOM%+10))
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

  clean
}
