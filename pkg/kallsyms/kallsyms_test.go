package kallsyms_test

import (
	"bytes"
	"cmp"
	"slices"
	"testing"

	"github.com/akerouanton/skbdump/pkg/kallsyms"
	"gotest.tools/v3/assert"
)

var goldenKallsyms = `ffff800080010000 T _stext
ffff800080010000 T __irqentry_text_start
ffff800080010008 t gic_handle_irq
ffff8000800100a0 t gic_handle_irq
ffff8000800101d4 T __irqentry_text_end
ffff80007a286000 t $x	[shiftfs]
ffff80007a286008 t shiftfs_inode_test	[shiftfs]
ffff80007a286028 t shiftfs_inode_set	[shiftfs]`

func TestLoadKallsyms(t *testing.T) {
	k, err := kallsyms.LoadKallsyms(bytes.NewBufferString(goldenKallsyms))
	assert.NilError(t, err)

	expected := kallsyms.Kallsyms{
		kallsyms.Ksym{StartAddr: 0xffff80007a286000, EndAddr: 0xffff80007a286007, Typ: "t", Name: "$x"},
		kallsyms.Ksym{StartAddr: 0xffff80007a286008, EndAddr: 0xffff80007a286027, Typ: "t", Name: "shiftfs_inode_test"},
		kallsyms.Ksym{StartAddr: 0xffff80007a286028, EndAddr: 0xffff80008000ffff, Typ: "t", Name: "shiftfs_inode_set"},
		kallsyms.Ksym{StartAddr: 0xffff800080010000, EndAddr: 0xffff800080010007, Typ: "T", Name: "__irqentry_text_start"},
		kallsyms.Ksym{StartAddr: 0xffff800080010008, EndAddr: 0xffff80008001009f, Typ: "t", Name: "gic_handle_irq"},
		kallsyms.Ksym{StartAddr: 0xffff8000800100a0, EndAddr: 0xffff8000800101d3, Typ: "t", Name: "gic_handle_irq"},
		kallsyms.Ksym{StartAddr: 0xffff8000800101d4, EndAddr: 0xffffffffffffffff, Typ: "T", Name: "__irqentry_text_end"},
	}
	assert.DeepEqual(t, k, expected)

	assert.Check(t, slices.IsSortedFunc(k, func(a, b kallsyms.Ksym) int {
		return cmp.Compare(a.StartAddr, b.StartAddr)
	}))
}

func TestSearchAddr(t *testing.T) {
	k, err := kallsyms.LoadKallsyms(bytes.NewBufferString(goldenKallsyms))
	assert.NilError(t, err)

	sym, found := k.SearchAddr(0xffff800080010000) // Exact start address
	assert.Check(t, found)
	assert.Equal(t, sym, "__irqentry_text_start")

	sym, found = k.SearchAddr(0xffff8000800100b9) // Address somewhere in the middle of a symbol
	assert.Check(t, found)
	assert.Equal(t, sym, "gic_handle_irq")

	sym, found = k.SearchAddr(0xffff8000800101d4) // Last symbol's exact start address
	assert.Check(t, found)
	assert.Equal(t, sym, "__irqentry_text_end")

	sym, found = k.SearchAddr(0xffff8000800101f0) // Address after the last known address
	assert.Check(t, found)
	assert.Equal(t, sym, "__irqentry_text_end")
}
