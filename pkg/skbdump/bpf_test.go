package skbdump

import (
	"encoding/binary"
	"testing"

	"gotest.tools/v3/assert"
)

func TestDecodeSKB(t *testing.T) {
	testcases := []struct {
		name string
		buf  []byte
		exp  SKB
	}{
		{
			name: "just a depth",
			buf:  []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			exp:  SKB{Depth: 1},
		},
		{
			name: "full fledged",
			buf: []byte{
				0x01, 0x92, 0xa9, 0x37, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xf8, 0xc6, 0x56, 0x6d, 0x17, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00,
				0x04, 0x00, 0x00, 0x00, 0x65, 0x74, 0x68, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0xff, 0xff,
			},
			exp: SKB{
				FuncAddr: 0,
				Depth:    1,
				Time:     148534688401144,
				Netns:    4026531840,
				IfIndex:  4,
				IfName:   "eth0",
				Payload:  []byte{},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			skb, err := decodeSKB(tc.buf, binary.LittleEndian)
			assert.NilError(t, err)
			assert.DeepEqual(t, skb, tc.exp)
		})
	}
}
