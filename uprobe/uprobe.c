// +build ignore

#include "common.h"
#include "bpf_tracing.h"
char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    int a;
    int b;
    int c;
    int d;
    int e;
    int f;
    int g;
    int h;
    int i;
    int j;
    int k;
    int l;
    int m;
    int n;
    int o;
    int p;
    int q;
    int w; //不明白原因，定义的成员数量要比参数的数量多1个，后面的代码才是正常的
};

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const struct event *unused __attribute__((unused));

SEC("uprobe/uprobe")
int trace_golang_sample(struct pt_regs *ctx)
{   
    struct event * e;
    e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
     
    if(!e){
        return 0;
    }

    e->a = PT_REGS_RC(ctx); 
    e->b = ctx->rbx; //可以直接获取寄存器
    e->c = PT_REGS_PARM4(ctx);
    e->d = PT_REGS_PARM1(ctx);
    e->e = PT_REGS_PARM2(ctx);
    e->f = PT_REGS_PARM5(ctx);
    e->g = ctx->r9;
    e->h = ctx->r10;
    e->i = ctx->r11;

    bpf_probe_read_user(&e->j, sizeof(__s64), (void *)ctx->rsp + sizeof(__s64));
    bpf_probe_read_user(&e->k, sizeof(__s64), (void *)ctx->rsp + sizeof(__s64)*2);
    bpf_probe_read_user(&e->l, sizeof(__s64), (void *)ctx->rsp + sizeof(__s64)*3);
    bpf_probe_read_user(&e->m, sizeof(__s64), (void *)ctx->rsp + sizeof(__s64)*4);
    bpf_probe_read_user(&e->n, sizeof(__s64), (void *)ctx->rsp + sizeof(__s64)*5);
    bpf_probe_read_user(&e->o, sizeof(__s64), (void *)ctx->rsp + sizeof(__s64)*6);
    bpf_probe_read_user(&e->p, sizeof(__s64), (void *)ctx->rsp + sizeof(__s64)*7);
    bpf_probe_read_user(&e->q, sizeof(__s64), (void *)ctx->rsp + sizeof(__s64)*8);
    bpf_ringbuf_submit(e, 0);
    return 0;
}