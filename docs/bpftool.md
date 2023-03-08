## bpftool

### install
```bash
# 下载kernel源码

sudo apt install -y linux-source

# 安装工具链

sudo apt install build-essential libncurses-dev bison flex libssl-dev libelf-dev dwarves libcap-dev -y

# 解压kernel压缩包

sudo tar -jxf /usr/src/linux-source-5.4.0.tar.bz2

cd linux-source-5.4.0/

# 安装libbfd需要的binutils开发包，没有libbfd会导致无法dump jit指令，会提示no libbfd support

sudo apt install -y binutils-dev
```
```bash
# 进kernel目录，编译和系统匹配的bpftool

make -C tools/bpf/bpftool/

# 安装编译好的bpftool

make install -C tools/bpf/bpftool/

# 执行bpftool工具，看dump

./tools/bpf/bpftool/bpftool prog dump jited id 52
```

### help
```bash
# 帮助命令

man 8 bpftool

man 8 bpftool-prog

man 8 bpftool-map

# 加载bpf程序，load加载一个，加载所有可以用loadall

bpftool prog load <prog> <pinned_path>

# 看有那些程序在运行

bpftool prog show

# 看byte code

bpftool prog dump xlated id 0

# 也支持用subcommand

bpftool p d i 0

# 看JIT翻译后的指令

bpftool prog dump jited id 0

# 看map

bpftool map show

# 找map entry，可以看到key和value的内容

bpftool map lookup id 1 key 0x01 0x00 0x00 0x00

# 看map entry

bpftool map dump id 1

# 更新一个map entry

bpftool map update id 182 key 3 0 0 0 value 1 1 168 192

# 运行预定义的数据，data_in是输入

bpftool prog run pinned /sys/fs/bpf/sample_ret0 data_in input data_out - repeat 10

# attach到socket

bpftool prog attach <prog> <attach type> <target map>

# attach到cgroup

bpftool cgroup attach <cgroup> <attach type> <prog> [flags]

# attach到tc或XDP

bpftool net attach <attach type> <program> <interface>

# 列出kernel的feature

bpftool feature probe kernel

# 看bpf_trace_printk()的输出

bpftool tracelog

# 从event map里dump出数据

bpftool map event_pipe id 42

# json的支持 -j|--json，或者-p|--pretty

# batch模式

bpftool batch file <file>
```