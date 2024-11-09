#include "skbdump.h"

#define skb_is_l2(skb) (skb->mac_header != skb->network_header)
#define linear_payload_len(skb) (skb->tail - (skb_is_l2(skb) ? skb->mac_header : skb->network_header))

static __always_inline int collect_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    __u16 payload_len = linear_payload_len(skb);

    struct skb_meta meta = {
	    .func_addr = BPF_CORE_READ(ctx, pc),
	    .time = bpf_ktime_get_ns(),
	    .netns = skb->dev->nd_net.net->ns.inum,
	    .ifindex = skb->dev->ifindex,
	    .is_l2 = skb_is_l2(skb),
	    .payload_len = payload_len + skb->data_len,
	};
	if (bpf_probe_read_kernel(meta.ifname, IFNAMSIZ, skb->dev->name) != 0) {
        bpf_printk("BUG! failed to read ifname");
        return -1;
    }

    if (!meta.is_l2) {
        bpf_printk("len: %d - data_len: %d - mac_header: %08x - network_header: %08x - transport_header: %08x - tail: %08x - payload_len: %08x",
            skb->len, skb->data_len, skb->mac_header, skb->network_header, skb->transport_header, skb->tail, payload_len);
    }

    struct bpf_dynptr ptr = {};
	if (bpf_ringbuf_reserve_dynptr(&ringbuf_payloads, sizeof(struct skb_meta) + payload_len, 0, &ptr) != 0) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
	    return -1;
	}

	if (bpf_dynptr_write(&ptr, 0, &meta, sizeof(meta), 0) != 0) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
	    return -1;
    }

    if (copy_payload_chunks_into_dynptr(&ptr, sizeof(struct skb_meta), skb->data, linear_payload_len(skb)) != 0) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return -1;
    }

    /* if (copy_frags_into_dynptr(&ptr, sizeof(struct skb_meta) + payload_len, skb) != 0) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return -1;
    } */

    bpf_ringbuf_submit_dynptr(&ptr, 0);
	return 0;
}

// TODO(aker): return a bool instead
static __always_inline int filter_skb(struct pt_regs *ctx, struct sk_buff *skb) {
	char comm[32];
	if (bpf_get_current_comm(&comm, sizeof(comm)) != 0) {
	    bpf_printk("BUG! failed to get comm");
	    return -1;
    }

    if (bpf_strncmp(comm, sizeof(comm), "lifecycle-serve") == 0) {
        return -1;
    }

    if (skb->mark == CGROUP_MARK) {
        // This packet was already processed by the cgroup_skb/egress prog. No
        // need to process it once again.
        return -1;
    }

    if (skb_is_l2(skb)) {
        __u16 ethertype = 0;
        if (bpf_probe_read_kernel(&ethertype, 2, (void *)(skb->data + 12)) != 0) {
            bpf_printk("BUG! failed to read ethertype");
        }
        if (bpf_htons(ethertype) == 0x0800) {
            // Ignore IPv4 frames -- they're going to be captured by cgroup progs.
            return -1;
        }
    }

    return 0;
}

#define SKB_FENTRY(FN, X)                                                   \
  SEC("fentry/" #FN)                                                        \
  int on_##FN(struct pt_regs *ctx) {                                        \
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM##X(ctx);          \
    if (filter_skb(ctx, skb) != 0) {                                        \
        return 0;                                                           \
    }                                                                       \
    if (collect_skb(ctx, skb) != 0) {                                       \
        incr_miss_counter();                                                \
    }                                                                       \
    return 0;                                                               \
  }

// TODO(aker): support tracing with kprobes (that seems to be the only way to
//             dump the PC register to track which function saw the SKB first).

SKB_FENTRY(veth_xmit, 1)
