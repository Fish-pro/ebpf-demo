#include "common.h"

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("xdp")
int xdp_drop_the_world(struct xdp_md *ctx) {
    // drop everything
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";