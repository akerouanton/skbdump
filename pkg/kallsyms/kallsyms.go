package kallsyms

import (
	"bufio"
	"cmp"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"sync"
)

type Ksym struct {
	StartAddr uint64
	EndAddr   uint64
	Typ       string
	Name      string
}

type Kallsyms []Ksym

func LoadKallsyms(r io.Reader) (Kallsyms, error) {
	var kallsyms []Ksym
	var err error

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var ksym Ksym
		var addr string
		if _, err := fmt.Sscanf(scanner.Text(), "%s %s %s", &addr, &ksym.Typ, &ksym.Name); err != nil {
			return Kallsyms{}, fmt.Errorf("LoadKallsyms: %w", err)
		}

		// Ignore the _stext symbol -- it's just an alias to the start of the .text section.
		if ksym.Name == "_stext" {
			continue
		}

		ksym.StartAddr, err = strconv.ParseUint(addr, 16, 64)
		if err != nil {
			return Kallsyms{}, fmt.Errorf("LoadKallsyms: %w", err)
		}

		kallsyms = append(kallsyms, ksym)
	}

	// Modules' symbols appear after compiled-in kernel's symbols in /dev/kallsyms,
	// but they have lower addresses since the stack grows downward. kallsyms need
	// to be sorted to allow SearchAddr to perform binary searches.
	slices.SortStableFunc(kallsyms, func(a, b Ksym) int {
		return cmp.Compare(a.StartAddr, b.StartAddr)
	})

	for i := 1; i < len(kallsyms); i++ {
		// We don't know exactly where a given symbol ends, but we infer that
		// based on the next symbol's StartAddr. This is used by SearchAddr to
		// perform binary searches.
		kallsyms[i-1].EndAddr = kallsyms[i].StartAddr - 1
	}

	if len(kallsyms) > 0 {
		// The last symbol has no next symbol, so we can only assume that any
		// address after its StartAddr matches it.
		kallsyms[len(kallsyms)-1].EndAddr = 0xffffffffffffffff
	}

	return kallsyms, nil
}

// SearchAddr looks for the symbol that spans over 'addr'.
func (kallsyms Kallsyms) SearchAddr(addr uint64) (string, bool) {
	pos, found := slices.BinarySearchFunc(kallsyms, addr, func(a Ksym, addr uint64) int {
		if addr >= a.StartAddr && addr <= a.EndAddr {
			return 0
		}
		return int(a.StartAddr - addr)
	})
	if !found {
		return "[unknown]", false
	}

	return kallsyms[pos].Name, true
}

var (
	kallsyms Kallsyms
	konce    sync.Once
	kerr     error
)

func SearchAddr(addr uint64) (string, bool, error) {
	konce.Do(func() {
		var f *os.File
		f, kerr = os.Open("/proc/kallsyms")
		if kerr != nil {
			return
		}

		kallsyms, kerr = LoadKallsyms(f)
		if kerr != nil {
			return
		}
	})

	if kerr != nil {
		return "", false, kerr
	}

	name, found := kallsyms.SearchAddr(addr)
	return name, found, nil
}
