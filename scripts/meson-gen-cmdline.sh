#!/bin/sh
# Génère cmdline.c / cmdline.h depuis gengetopt + patch (équivalent Automake).
set -e
srcdir="$1"
outdir="$2"
cd "$outdir"
cat "$srcdir/cmdline.ggo" | gengetopt -C
cp cmdline.c cmdline.c.orig
patch -p0 <"$srcdir/cmdline.patch"
