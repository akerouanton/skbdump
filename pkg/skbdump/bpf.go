package skbdump

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed tracer.o
var tracerBPF []byte

func loadPrograms(filter string) (_ *ebpf.Collection, _ *ebpf.CollectionSpec, retErr error) {
	collSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tracerBPF))
	if err != nil {
		return nil, nil, fmt.Errorf("could not load collection spec: %w", err)
	}

	/* for name, spec := range collSpec.Programs {
		if name == "on_kfree_skbmem" {
			continue
		}

		if spec.Instructions, err = elibpcap.Inject(filter, spec.Instructions, elibpcap.Options{
			AtBpf2Bpf:  "fentry_pcap_filter_l2",
			DirectRead: true,
			L2Skb:      true,
		}); err != nil {
			return nil, nil, fmt.Errorf("failed to inject l2 pcap filter into %s: %w", name, err)
		}

		if spec.Instructions, err = elibpcap.Inject(filter, spec.Instructions, elibpcap.Options{
			AtBpf2Bpf:  "fentry_pcap_filter_l3",
			DirectRead: true,
			L2Skb:      false,
		}); err != nil {
			return nil, nil, fmt.Errorf("failed to inject l3 pcap filter into %s: %w", name, err)
		}
	} */

	coll, err := ebpf.NewCollectionWithOptions(collSpec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return nil, nil, fmt.Errorf("could not load BPF objects from collection spec: %s", strings.Join(verr.Log, "\n"))
		}
		return nil, nil, fmt.Errorf("could not load BPF objects from collection spec: %w", err)
	}
	defer func() {
		if retErr != nil {
			coll.Close()
		}
	}()

	return coll, collSpec, nil
}

func attachPrograms(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec, cgroup string) (_ []link.Link, retErr error) {
	var links []link.Link
	defer func() {
		if retErr == nil {
			return
		}
		for _, link := range links {
			link.Close()
		}
	}()

	var err error
	for name, spec := range collSpec.Programs {
		prog := coll.Programs[name]

		var l link.Link
		switch prog.Type() {
		case ebpf.Kprobe:
			l, err = link.Kprobe(spec.AttachTo, prog, nil)
		case ebpf.Tracing:
			l, err = link.AttachTracing(link.TracingOptions{
				Program:    coll.Programs[name],
				AttachType: spec.AttachType,
			})
		case ebpf.CGroupSKB:
			attachType := ebpf.AttachCGroupInetIngress
			if spec.SectionName == "cgroup_skb/egress" {
				attachType = ebpf.AttachCGroupInetEgress
			}
			l, err = link.AttachCgroup(link.CgroupOptions{
				Path: cgroup,
				// TODO(aker): determine why cilium/ebpf doesn't set spec.AttachType
				Attach:  attachType,
				Program: prog,
			})
		default:
			return nil, fmt.Errorf("unsupported program type %s", prog.Type())
		}

		if err != nil {
			return nil, fmt.Errorf("failed to attach prog %s: %w", name, err)
		}

		links = append(links, l)
	}

	return links, nil
}

type missCounter uint64

// aligo:ignore
type SKB struct {
	FuncAddr   uint64
	Time       time.Time
	Netns      uint64
	IfIndex    uint32
	IfName     string
	PayloadLen int
	IsL2       bool
	Payload    []byte
}

type rawSKB struct {
	FuncAddr   uint64   `align:"func_addr"`
	Time       uint64   `align:"time"`
	Netns      uint64   `align:"netns"`
	IfIndex    uint32   `align:"ifindex"`
	IfName     [16]byte `align:"ifname"`
	IsL2       bool     `align:"is_l2"`
	_          [1]uint8
	PayloadLen uint16 `align:"payload_len"`
}

var (
	szRawSKB            = int(unsafe.Sizeof(rawSKB{}))
	blankEthernetHeader = make([]byte, 14)
)

func decodeSKB(buf []byte, byteOrder binary.ByteOrder) (SKB, error) {
	if len(buf) < szRawSKB {
		return SKB{}, fmt.Errorf("invalid sample size: %d (expected min. %d)", len(buf), szRawSKB)
	}

	var raw rawSKB
	r := bytes.NewBuffer(buf)
	if err := binary.Read(r, byteOrder, &raw); err != nil {
		return SKB{}, err
	}

	payload := r.Bytes()
	payloadLen := int(raw.PayloadLen)
	if !raw.IsL2 {
		payload = prependEtherHeader(payload)
		payloadLen += len(blankEthernetHeader)
	}

	return SKB{
		FuncAddr:   raw.FuncAddr,
		Time:       time.Unix(0, int64(raw.Time)), // TODO(aker): use proper conversion to avoid int64 overflow + this is currently broken
		Netns:      raw.Netns,
		IfIndex:    raw.IfIndex,
		IfName:     strings.Trim(string(raw.IfName[:]), "\x00"),
		PayloadLen: payloadLen,
		Payload:    payload,
	}, nil
}

func prependEtherHeader(payload []byte) []byte {
	off := 14
	if len(payload) < off {
		off = len(payload)
	}

	payload = append(payload, blankEthernetHeader...)
	copy(payload[14:], payload)
	copy(payload[:14], blankEthernetHeader)

	payload[12] = 0x08

	ipv := payload[14] & 0xf0
	if ipv == 4 {
		payload[12] = 0x08
	} else {
		payload[12] = 0x86
		payload[13] = 0xdd
	}

	return payload
}
