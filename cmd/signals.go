package main

import (
	"os/signal"
	"syscall"
)

// ignoreSIGPIPE makes a write to a closed stdout or stderr return EPIPE
// instead of killing the process. Go's default is to exit on SIGPIPE for
// fds 1 and 2, which would skip the metrics push and the exit code that a
// failed report write is meant to produce.
func ignoreSIGPIPE() {
	signal.Ignore(syscall.SIGPIPE)
}
