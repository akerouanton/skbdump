#include "skbdump.h"

static __always_inline int copy_skb_into_dynptr(struct bpf_dynptr *dst, __u16 dst_offset, struct __sk_buff *skb) {
    __u8 chunk_cnt = skb->len / CHUNK_SIZE;
    if (skb->len % CHUNK_SIZE > 0 && chunk_cnt < 255) {
        chunk_cnt++;
    }

    for (__u8 i = 0; i < chunk_cnt; i++) {
        __u16 chunk_off = i * CHUNK_SIZE;
        __u16 chunk_len = skb->len - chunk_off;

        if (chunk_len > CHUNK_SIZE) {
            chunk_len = CHUNK_SIZE;
        }
        if (chunk_len == 0) {
            break;
        }

        __u8 chunk[CHUNK_SIZE];
        if (bpf_skb_load_bytes(skb, chunk_off, chunk, chunk_len) != 0) {
            bpf_printk("BUG! bpf_skb_load_bytes != 0");
            return -1;
        }

        if (bpf_dynptr_write(dst, dst_offset + chunk_off, chunk, chunk_len, 0) != 0) {
            bpf_printk("BUG! failed to write chunk into dynptr.");
            return -1;
        }
    }

    return 0;
}

static __always_inline int collect_cgroup_skb(struct __sk_buff *skb) {
    __u16 payload_len = skb->len;

    struct skb_meta meta = {
	    .time = bpf_ktime_get_ns(),
	    // .netns_cookie = bpf_get_netns_cookie(skb),
	    .ifindex = skb->ifindex,
	    .payload_len = payload_len,
	};

    struct bpf_dynptr ptr = {};
	if (bpf_ringbuf_reserve_dynptr(&ringbuf_payloads, sizeof(struct skb_meta) + payload_len, 0, &ptr) != 0) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
	    return -1;
	}

	if (bpf_dynptr_write(&ptr, 0, &meta, sizeof(meta), 0) != 0) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
	    return -1;
    }

    if (copy_skb_into_dynptr(&ptr, sizeof(struct skb_meta), skb) != 0) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return -1;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
	return 0;
}

SEC("cgroup_skb/ingress")
int on_ingress(struct __sk_buff *skb) {
    if (collect_cgroup_skb(skb) != 0) {
        incr_miss_counter();
    }
    return 1;
}

SEC("cgroup_skb/egress")
int on_egress(struct __sk_buff *skb) {
    if (collect_cgroup_skb(skb) != 0) {
        incr_miss_counter();
    }
    skb->mark = CGROUP_MARK;
    return 1;
}
