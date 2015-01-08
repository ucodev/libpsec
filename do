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
fi

echo "" >> .defines

if [ `uname -m` = "armv6l" ]; then
	if [ "`cat .target`" == "rpi" ]; then
		echo "-ccc-host-triple armv6-unknown-eabi -march=armv6 -mfpu=vfp -mcpu=arm1176jzf-s -mtune=arm1176jzf-s -mfloat-abi=hard" > .archflags
	else
		echo "-march=armv6" > .archflags
	fi
else
	echo "" > .archflags
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

./features

exit 0

