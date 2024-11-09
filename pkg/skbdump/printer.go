package skbdump

import (
	"encoding/hex"
	"fmt"

	"github.com/akerouanton/skbdump/pkg/kallsyms"
)

func PrintSKB(skb SKB) error {
	ksym, _, err := kallsyms.SearchAddr(skb.FuncAddr)
	if err != nil {
		return err
	}

	iface := skb.IfName
	if len(iface) == 0 {
		iface = fmt.Sprintf("ifi:%d", skb.IfIndex)
	}

	fmt.Printf("%d.%d: %s: %s@netns:%d\n", skb.Time.Second(), skb.Time.Nanosecond(), ksym, iface, skb.Netns)
	fmt.Printf("%s\n\n", hex.Dump(skb.Payload))
	return nil
}
