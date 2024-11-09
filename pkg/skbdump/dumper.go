package skbdump

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	mapPayloads = "ringbuf_payloads"
	mapMisses   = "misses"
)

type Config struct {
	// Filter in pcap format
	Filter string
	// CGroup is the path to the cgroup v2 hierarchy where cgroup programs
	// should be attached. BPF programs will capture userspace-generated/destined
	// for this specific cgroup, and all its children. See
	// https://elixir.bootlin.com/linux/v6.11.6/source/kernel/bpf/cgroup.c#L595
	CGroup string
}

type Dumper struct {
	ringbuf   *ringbuf.Reader
	links     []link.Link
	coll      *ebpf.Collection
	byteOrder binary.ByteOrder
}

// NewDumper takes a pcap filter and returns a new Dumper.
func NewDumper(cfg Config) (_ *Dumper, retErr error) {
	coll, collSpec, err := loadPrograms(cfg.Filter)
	if err != nil {
		return nil, err
	}

	links, err := attachPrograms(coll, collSpec, cfg.CGroup)
	if err != nil {
		return nil, err
	}

	r, err := ringbuf.NewReader(coll.Maps[mapPayloads])
	if err != nil {
		return nil, fmt.Errorf("create ringbuf reader %s: %w", mapPayloads, err)
	}

	return &Dumper{
		ringbuf:   r,
		links:     links,
		coll:      coll,
		byteOrder: collSpec.ByteOrder,
	}, nil
}

func (d *Dumper) Run(ch chan<- SKB) error {
	for {
		rec, err := d.ringbuf.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			return fmt.Errorf("reading from ringbuf: %w", err)
		}

		skb, err := decodeSKB(rec.RawSample[:], d.byteOrder)
		if err != nil {
			log.Printf("could not decode ringbuf sample: %v", err)
			continue
		}

		if skb.Netns == 4026531840 {
			continue
		}

		ch <- skb
	}
}

func (d *Dumper) QueryMisses() uint {
	it := d.coll.Maps[mapMisses].Iterate()

	var k uint32
	var sum uint
	// mapMisses has max_entries=1, but it's a per-CPU map, so it.Next returns
	// a slice of values - sum them up.
	var values []missCounter
	for it.Next(&k, &values) {
		for _, v := range values {
			sum += uint(v)
		}
	}

	return sum
}

func (d *Dumper) Close() {
	d.ringbuf.Close()

	for _, l := range d.links {
		l.Close()
	}
	for _, m := range d.coll.Maps {
		m.Close()
	}
}
