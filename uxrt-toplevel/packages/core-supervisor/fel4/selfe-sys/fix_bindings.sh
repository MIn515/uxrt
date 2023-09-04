#!/bin/sh
TMPFILE="`mktemp`"

trap "rm -f $TMPFILE" HUP INT EXIT

sed -f fix_bindings.sed < "$1" > "$TMPFILE"
mv "$TMPFILE" "$1"
