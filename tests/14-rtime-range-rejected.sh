#!/bin/sh

# Goal of this test:
# - reject DNS re-resolution intervals which cannot be represented safely by
#   the event timer instead of turning them into already-expired timers.

process_running() {
	kill -0 "$1" 2>/dev/null
}

check_rtime_rejected() {
	rtime=$1
	label=$2
	spiped_stderr="${s_basename}-${label}.stderr"
	source_sock="${s_basename}-${label}.sock"

	"${spiped_binary}" -d -F \
	    -s "${source_sock}" \
	    -t "${dst_sock}" \
	    -k /dev/null \
	    -r "${rtime}" > /dev/null 2> "${spiped_stderr}" &
	pid=$!

	# An unfixed binary remains alive, repeatedly re-resolving DNS.  Give the
	# repaired binary a bounded interval in which to reject the timer.
	if wait_while 1000 process_running "${pid}"; then
		if wait "${pid}"; then
			exitcode=0
		else
			exitcode=$?
		fi
		if [ "${exitcode}" -eq 1 ] &&
		    grep -q 'Failed to initialize connection acceptor' \
		    "${spiped_stderr}"; then
			rc=0
		else
			rc=1
		fi
	else
		kill "${pid}" 2>/dev/null || true
		wait "${pid}" 2>/dev/null || true
		rc=1
	fi

	rm -f "${spiped_stderr}" "${source_sock}"
	return "${rc}"
}

scenario_cmd() {
	setup_check "reject infinite DNS re-resolution interval"
	if check_rtime_rejected inf inf; then
		echo 0 > "${c_exitfile}"
	else
		echo 1 > "${c_exitfile}"
	fi

	setup_check "reject huge finite DNS re-resolution interval"
	if check_rtime_rejected 1e308 huge; then
		echo 0 > "${c_exitfile}"
	else
		echo 1 > "${c_exitfile}"
	fi
}
