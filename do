#!/bin/bash

if [ -e "/usr/bin/clang" ]; then
	echo "/usr/bin/clang" > .compiler
elif [ -e "/usr/bin/gcc" ]; then
	echo "/usr/bin/gcc" > .compiler
elif [ -e "/usr/bin/cc" ]; then
	echo "/usr/bin/cc" > .compiler
else
	echo "No suitable compiler found."
	exit 1
fi

if [ `uname` == "Linux" ]; then
	echo "-D_GNU_SOURCE -D_XOPEN_SOURCE=700" > .defines
elif [ `uname`== "Darwin" ]; then
	echo "-D_XOPEN_SOURCE=700" > .defines
else
	echo "" > .defines
fi

if [ ! -e "/usr/bin/ld" ]; then
	echo "/usr/bin/ld not found."
	exit 1
fi

## Test features ##
mkdir -p build
rm -f .l*
. test.inc

test_lib "crypt"
test_lib "gmp"

# Build
make

if [ $? -ne 0 ]; then
	echo "Build failed."
	exit 1
fi

touch .done

echo "Build completed."

exit 0

