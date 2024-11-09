#pragma once

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define IFNAMSIZ 16
#define CHUNK_SIZE 256
#define CGROUP_MARK 0x01020304

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} misses SEC(".maps");

static __always_inline void incr_miss_counter() {
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&misses, &key);
    __u64 ctr = 0;
    if (counter != NULL) {
        ctr = *counter;
    }

    ctr++;
    bpf_map_update_elem(&misses, &key, &ctr, BPF_ANY);

    return;
}

struct skb_meta {
    __u64 func_addr; // Instruction pointer
    __u64 time;      // time in ns
    __u64 netns;     // netns inode number
    __u32 ifindex;   // iface id in netns
    char ifname[IFNAMSIZ];
    __u8 is_l2;
    __u16 payload_len; // Linear + non-linear length
};

const struct skb_meta *unused_skb_meta __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<24); // = 16 MiB, max_entries on a ringbuf is its size in bytes.
} ringbuf_payloads SEC(".maps");

// We can't write dynptrs from 'untrusted sources' like an skb. Instead, we
// need to read the skb chunk by chunk in an intermediate buffer, and then
// use that buf to write the dynptr. But then comes another problem: BPF
// stack is really small, so we can't use "big" chunks (eg. >256 bytes).
//
// For now, use a small chunk size, but revisit this later if needed.
//
//      ; if (bpf_dynptr_write(&ptr, sizeof(struct skb_meta), skb->data, skb->end, 0) != 0) { @ bpf.c:104
//      130: (61) r4 = *(u32 *)(r6 +188)      ; R4_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R6=ptr_sk_buff() refs=3
//      131: (79) r3 = *(u64 *)(r6 +200)      ; R3_w=scalar() R6=ptr_sk_buff() refs=3
//      132: (bf) r1 = r10                    ; R1_w=fp0 R10=fp0 refs=3
//      133: (07) r1 += -64                   ; R1_w=fp-64 refs=3
//      134: (b7) r6 = 0                      ; R6_w=0 refs=3
//      135: (b7) r2 = 40                     ; R2_w=40 refs=3
//      136: (b7) r5 = 0                      ; R5_w=0 refs=3
//      137: (85) call bpf_dynptr_write#202
//      R3 type=scalar expected=fp, pkt, pkt_meta, map_key, map_value, mem, ringbuf_mem, buf, trusted_ptr_
//      processed 123 insns (limit 1000000) max_states_per_insn 1 total_states 8 peak_states 8 mark_read 3
//
// See https://lore.kernel.org/bpf/MEYP282MB2312CFCE5F7712FDE313215AC64D2@MEYP282MB2312.AUSP282.PROD.OUTLOOK.COM/T/
static __always_inline int copy_payload_chunks_into_dynptr(struct bpf_dynptr *dst, __u16 dst_offset, void *src, __u16 src_len) {
    __u8 chunk_cnt = src_len / CHUNK_SIZE;
    if (src_len % CHUNK_SIZE > 0 && chunk_cnt < 255) {
        chunk_cnt++;
    }

    for (__u8 i = 0; i < chunk_cnt; i++) {
        __u16 chunk_off = i * CHUNK_SIZE;
        __u16 chunk_len = src_len - chunk_off;

        if (chunk_len > CHUNK_SIZE) {
            chunk_len = CHUNK_SIZE;
        }

        __u8 chunk[CHUNK_SIZE];
        if (bpf_probe_read_kernel(chunk, chunk_len, src + chunk_off) != 0) {
            bpf_printk("BUG! failed to read chunk from skb.");
            return -1;
        }

        if (bpf_dynptr_write(dst, dst_offset + chunk_off, chunk, chunk_len, 0) != 0) {
            bpf_printk("BUG! failed to write chunk into dynptr.");
            return -1;
        }
    }

    return 0;
}
