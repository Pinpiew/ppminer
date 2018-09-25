#!/bin/bash

#if [ "$OS" = "Windows_NT" ]; then
#    ./mingw64.sh
#    exit 0
#fi

# Linux build

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done

CFLAGS="-g -O3 -march=native -Wall" ./configure

make -j 4

strip -s ppminer
