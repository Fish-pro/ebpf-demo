//go:build ignore

#include "common.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

SEC("kprobe/do_sys_openat2")
int kprobe_openat2(struct pt_regs *ctx) {
	u32 key     = 0;
	u64 initval = 1, *valp;
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	valp = bpf_map_lookup_elem(&kprobe_map, &key);
	if (!valp){
		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
	}else{
		__sync_fetch_and_add(valp, 1);
	}

	char filename[20];
	const char *fp = (char *)PT_REGS_PARM2(ctx);
	long err = bpf_probe_read_user_str(filename, sizeof(filename), fp);
	bpf_printk("pid:%d,filename:%s,err:%ld",pid,filename,err);

	return 0;
}
