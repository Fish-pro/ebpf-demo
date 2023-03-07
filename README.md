# ebpf-demo

## demo
### Create vm

```bash
vm create ebpf ubuntu22
```

### Modify gateway

`vi /etc/netplan/ens192.yaml`
```bash
network:
  version: 2
  renderer: networkd
  ethernets:
    eno1:
      dhcp4: false
      dhcp6: false
     addresses:
      - 172.19.4.152/24 #修改为你的静态ip地址
     routes:
      - to: default
        via: 172.19.4.1 #配置网关（原有gateway4已弃用
     nameservers:
      addresses: [114.114.114.114]
version: 2
```
```bash
reboot
```

### Install simple basic tools
```bash
apt-get update
apt-get install openssh-server vim git tree
```

### Install golang
```
wget https://dl.google.com/go/go1.19.linux-amd64.tar.gz
tar -C /usr/local/ -xzf go1.19.linux-amd64.tar.gz
mkdir go
cat >> .profile << EOF
export GOROOT=/usr/local/go
export GOPATH=/root/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
export GO111MODULE="on" 
export GOPROXY=https://goproxy.cn,direct
EOF
source .profile
```

### Installation dependency
```bash
apt install clang llvm
```

### Configure environment variables
```bash
export BPF_CLANG=clang
```

### Clone cilium/ebpf to a local directory
```bash
mkdir -p $GOPATH/src/github.com/cilium
cd $GOPATH/src/github.com/cilium
git clone https://github.com/cilium/ebpf.git
```

### test
```bash
root@york-ebpf:~/go/src/github.com# cd cilium/ebpf/examples/kprobe
root@york-ebpf:~/go/src/github.com/cilium/ebpf/examples/kprobe# tree
.
├── bpf_bpfeb.go
├── bpf_bpfeb.o
├── bpf_bpfel.go
├── bpf_bpfel.o
├── kprobe.c
└── main.go

0 directories, 6 files
root@york-ebpf:~/go/src/github.com/cilium/ebpf/examples/kprobe# rm -rf *.o bpf_*.go
root@york-ebpf:~/go/src/github.com/cilium/ebpf/examples/kprobe# go generate
Compiled /root/go/src/github.com/cilium/ebpf/examples/kprobe/bpf_bpfel.o
Stripped /root/go/src/github.com/cilium/ebpf/examples/kprobe/bpf_bpfel.o
Wrote /root/go/src/github.com/cilium/ebpf/examples/kprobe/bpf_bpfel.go
Compiled /root/go/src/github.com/cilium/ebpf/examples/kprobe/bpf_bpfeb.o
Stripped /root/go/src/github.com/cilium/ebpf/examples/kprobe/bpf_bpfeb.o
Wrote /root/go/src/github.com/cilium/ebpf/examples/kprobe/bpf_bpfeb.go
root@york-ebpf:~/go/src/github.com/cilium/ebpf/examples/kprobe# tree
.
├── bpf_bpfeb.go
├── bpf_bpfeb.o
├── bpf_bpfel.go
├── bpf_bpfel.o
├── kprobe.c
└── main.go

0 directories, 6 files
```
```bash
root@york-ebpf:~/go/src/github.com/cilium/ebpf/examples/kprobe# go build
root@york-ebpf:~/go/src/github.com/cilium/ebpf/examples/kprobe# tree
.
├── bpf_bpfeb.go
├── bpf_bpfeb.o
├── bpf_bpfel.go
├── bpf_bpfel.o
├── kprobe
├── kprobe.c
└── main.go
root@york-ebpf:~/go/src/github.com/cilium/ebpf/examples/kprobe# sudo ./kprobe
2023/03/07 06:45:20 Waiting for events..
2023/03/07 06:45:32 sys_execve called 0 times
2023/03/07 06:45:33 sys_execve called 0 times
2023/03/07 06:45:34 sys_execve called 0 times
2023/03/07 06:45:35 sys_execve called 0 times
2023/03/07 06:45:36 sys_execve called 1 times
2023/03/07 06:45:37 sys_execve called 1 times
2023/03/07 06:45:44 sys_execve called 1 times
2023/03/07 06:45:45 sys_execve called 24 times
2023/03/07 06:45:46 sys_execve called 34 times
```

## Create your own Cilium eBPF project

```bash
cd $GOPATH/src/github.com/cilium/
mkdir ebpf-demo
cd ebpf-demo
cp -r ../ebpf/examples/headers/ ./
cp ../ebpf/examples/kprobe/main.go ./
cp ../ebpf/examples/kprobe/kprobe.c ./
```

`vim main.go`
```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -c    flags $BPF_CFLAGS bpf kprobe.c -- -I../headers
```
to
```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -c    flags $BPF_CFLAGS bpf kprobe.c -- -I./headers
```

```bash
go mod init 
go mod tidy
go generate && go build

root@york-ebpf:~/go/src/github.com/cilium/ebpf-demo# tree
.
├── bpf_bpfeb.go
├── bpf_bpfeb.o
├── bpf_bpfel.go
├── bpf_bpfel.o
├── ebpf-demo
├── go.mod
├── go.sum
├── headers
│   ├── LICENSE.BSD-2-Clause
│   ├── bpf_endian.h
│   ├── bpf_helper_defs.h
│   ├── bpf_helpers.h
│   ├── bpf_tracing.h
│   ├── common.h
│   └── update.sh
├── kprobe.c
└── main.go

1 directory, 16 files
```

kprobe.c

```c
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
```

```bash
go generate
```

main.go
```go
// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS --target=amd64 bpf kprobe.c -- -I./headers

const mapKey uint32 = 0

func main() {

	// Name of the kernel function to trace.
	fn := "do_sys_openat2"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.KprobeOpenat2, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	for range ticker.C {
		var value uint64
		if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("%s called %d times\n", fn, value)
	}
}
```

```bash
go build
sudo ./ebpf-demo
```

```bash
sudo cat /sys/kernel/debug/tracing/trace
```

