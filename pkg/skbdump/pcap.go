package skbdump

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PCAPWriter struct {
	w      *pcapgo.NgWriter
	ifaces map[string]int
}

// tcpdump won't read a pcap file if the link type of all interfaces isn't the
// same.
const linkType = layers.LinkTypeEthernet

func NewPCAPWriter(w io.Writer) (_ *PCAPWriter, retErr error) {
	ngw, err := pcapgo.NewNgWriterInterface(w, pcapgo.NgInterface{
		OS:                  runtime.GOOS,
		LinkType:            linkType,
		TimestampResolution: 9, // nanosecond
		SnapLength:          0, // unlimited
	}, pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{
			Hardware:    runtime.GOARCH,
			OS:          runtime.GOOS,
			Application: "skbdump",
		},
	})
	if err != nil {
		return nil, err
	}

	if err := ngw.Flush(); err != nil {
		return nil, err
	}

	return &PCAPWriter{
		w:      ngw,
		ifaces: make(map[string]int),
	}, nil
}

func (w *PCAPWriter) WriteSKB(skb SKB) error {
	iface := fmt.Sprintf("%s@%d", skb.IfName, skb.Netns)
	iid, ok := w.ifaces[iface]
	if !ok {
		var err error
		iid, err = w.w.AddInterface(pcapgo.NgInterface{
			Name:                iface,
			OS:                  runtime.GOOS,
			LinkType:            linkType,
			TimestampResolution: 9,
			SnapLength:          0,
		})
		if err != nil {
			return err
		}

		w.ifaces[iface] = iid
	}

	captureLen := len(skb.Payload)
	pktLen := skb.PayloadLen // payload might be truncated if some of the original packet was stored in non-linear fragments
	if pktLen < captureLen {
		fmt.Fprintf(os.Stderr, "BUG! pktLen %d < captureLen %d\n", pktLen, captureLen)
		pktLen = captureLen
	}

	return w.w.WritePacket(gopacket.CaptureInfo{
		Timestamp:      skb.Time,
		CaptureLength:  captureLen,
		Length:         pktLen,
		InterfaceIndex: iid,
	}, skb.Payload)
}

func (w *PCAPWriter) Flush() error {
	return w.w.Flush()
}

func (w *PCAPWriter) Close() error {
	return w.w.Flush()
}
