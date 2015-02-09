#!/bin/sh

## Detect compiler ##
. ./lib/sh/compiler.inc

## Detect architecture ##
. ./lib/sh/arch.inc

## Target options ##
if [ `uname` = "Linux" ]; then
	echo "-D_GNU_SOURCE -D_XOPEN_SOURCE=700" > .defines
elif [ `uname` = "Darwin" ]; then
	echo "-D_XOPEN_SOURCE=700 -DNO_SHADOW_H=1" > .defines
elif [ `uname` = "FreeBSD" ]; then
	echo "-D_XOPEN_SOURCE=700 -DNO_SHADOW_H=1" > .defines
elif [ `uname` = "OpenBSD" ]; then
	echo "-D_XOPEN_SOURCE=700 -DNO_SHADOW_H=1" > .defines
fi

echo "" >> .defines

if [ ! -e "`which ld`" ]; then
	echo "ld not found."
	exit 1
fi

## Test features ##
mkdir -p build
rm -f .l*

. lib/sh/test.inc

test_lib "crypt"
test_lib "gmp"

## Build ##
make

if [ $? -ne 0 ]; then
	echo "Build failed."
	exit 1
fi

touch .done

echo "Build completed."

./features

exit 0

