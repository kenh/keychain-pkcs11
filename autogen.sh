#!/bin/sh

if [ ! -d m4 ]; then
	echo "Creating m4 directory"
	mkdir m4 || exit 1
fi

if command -v glibtoolize >/dev/null; then
	export LIBTOOLIZE=glibtoolize
elif command -v libtoolize > /dev/null; then
	export LIBTOOLIZE=libtoolize
else
	echo "Cannot find glibtoolize or libtoolize in path"
	exit 1
fi

echo "Running autoreconf ..."
set -ex
autoreconf -v -i
