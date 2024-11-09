//go:build aligncheck
// +build aligncheck

package main

import (
	"fmt"
	"os"

	"github.com/akerouanton/skbdump/pkg/skbdump"
	"github.com/cilium/cilium/pkg/alignchecker"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <path>\n", os.Args[0])
		os.Exit(1)
	}

	if err := check(os.Args[1]); err != nil {
		fmt.Printf("ERROR: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("SUCCESS: no errors found.\n")
}

func check(bpfObjPath string) error {
	if _, err := os.Stat(bpfObjPath); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot check alignment against %s: %s\n", bpfObjPath, err)
		os.Exit(1)
	}

	// Validate alignments of C and Go equivalent structs
	if err := alignchecker.CheckStructAlignments(bpfObjPath, map[string][]any{
		"skb_meta": {skbdump.RawSKB{}},
	}, true); err != nil {
		return err
	}

	// Validate the size of C and Go equivalent structs
	// TODO(aker): fix that
	return alignchecker.CheckStructAlignments(bpfObjPath, map[string][]any{
		// "misses": {skbdump.MissCounter(0)},
	}, false)
}
