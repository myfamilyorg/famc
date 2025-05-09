#!/bin/bash
set -e
export RUSTC_VERSION=1.29.0 MRUSTC_TARGET_VER=1.29 OUTDIR_SUF=-1.29.0
make
mkdir -p output-1.29.0
./bin/mrustc ./rustc-1.29.0-src/src/libcore/lib.rs \
	-o output-1.29.0/libcore.rlib \
	-C emit-depfile=output-1.29.0/libcore.rlib.d \
	--cfg debug_assertions \
	-O -L output-1.29.0 \
	--crate-name core \
	--crate-type rlib \
	--crate-tag 0_0_0 > output-1.29.0/libcore.rlib_dbg.txt
