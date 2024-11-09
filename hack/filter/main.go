package main

import (
	"fmt"
	"os"

	"github.com/cloudflare/cbpfc"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

func main() {
	cbpfInsns, err := NewFilter(os.Getenv("FILTER"))
	if err != nil {
		panic(err)
	}

	cbpfInsns = []bpf.Instruction{
		bpf.RawInstruction{0x28, 0, 0, 0x0000000c},
		bpf.RawInstruction{0x15, 0, 5, 0x00000800},
		bpf.RawInstruction{0x20, 0, 0, 0x0000001a},
		bpf.RawInstruction{0x15, 2, 0, 0xc0a84107},
		bpf.RawInstruction{0x20, 0, 0, 0x0000001e},
		bpf.RawInstruction{0x15, 0, 1, 0xc0a84107},
		bpf.RawInstruction{0x6, 0, 0, 0x00000000},
		bpf.RawInstruction{0x6, 0, 0, 0x00040000},
	}

	source, err := cbpfc.ToC(cbpfInsns, cbpfc.COpts{
		FunctionName: "filter_skb_l2",
		NoInline:     false,
	})
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile("bpf/filter.h", []byte(source), 0644); err != nil {
		panic(err)
	}
}

func NewFilter(rawFilter string) ([]bpf.Instruction, error) {
	insns, err := pcap.CompileBPFFilter(12, -1, rawFilter)
	if err != nil {
		return nil, fmt.Errorf("invalid filter %q: %w", rawFilter, err)
	}

	bpfInsns := make([]bpf.Instruction, len(insns))
	for i, insn := range insns {
		bpfInsns[i] = bpf.RawInstruction{
			Op: insn.Code,
			Jt: insn.Jt,
			Jf: insn.Jf,
			K:  insn.K,
		}
		fmt.Printf("{ 0x%02x, %d, %d, 0x%08x },\n", insn.Code, insn.Jt, insn.Jf, insn.K)
	}

	return bpfInsns, nil
}
