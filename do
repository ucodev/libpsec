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

mkdir -p build

## Test features ##

# test gmp support
echo 'int main(void) { return 0; }' > build/test.c && clang -o build/test build/test.c -lgmp

if [ $? -eq 0 ]; then
	touch .lgmp
	echo -ne '-lgmp ' >> .libs
fi

rm -f build/test build/test.c

# Build
make

if [ $? -ne 0 ]; then
	echo "Build failed."
	exit 1
fi

touch .done

echo "Build completed."

exit 0

