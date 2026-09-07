#!/bin/sh
# Exercise -r / -R argument validation only. usage() writes "usage:" to stderr
# and exit(1)s inside the sanity-check block, before any address resolution,
# so none of this touches a socket or needs a running peer.
LABEL="$1"
BIN=./spiped/spiped
BASE="-e -s [127.0.0.1]:8081 -t [127.0.0.1]:8082 -k /tmp/key"

echo "=========== $LABEL ==========="

run_case() {
	DESC="$1"
	shift
	OUT=$("$BIN" $BASE "$@" 2>&1 >/dev/null)
	RC=$?
	if echo "$OUT" | grep -q "^usage:"; then
		VERDICT=REJECTED
	else
		VERDICT=NOT-REJECTED
	fi
	printf '%-14s rc=%-3s %s\n' "$DESC" "$RC" "$VERDICT"
}

run_case '-r 30 -R' -r 30 -R
run_case '-r 60 -R' -r 60 -R
run_case '-r 0 -R'  -r 0 -R
run_case '-r 60'    -r 60
run_case '-R'       -R
echo "=========== end $LABEL ==========="
