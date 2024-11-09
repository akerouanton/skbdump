package main

import (
	"os"

	"github.com/akerouanton/skbdump/pkg/skbdump"
)

type writer struct {
	f     *os.File            // f is non-nil if the writer is writing a pcap.
	w     *skbdump.PCAPWriter // w is non-nil if the writer is writing a pcap.
	write func(skbdump.SKB) error
}

func (w writer) Close() {
	if w.w != nil {
		w.w.Close()
	}
	if w.f != nil {
		w.w.Close()
	}
}
