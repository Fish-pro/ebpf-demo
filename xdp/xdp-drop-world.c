//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
    // drop everything
    return XDP_DROP;
}
