# SNIPER-EBPF

## Clone

The command below will clone submodule libbpf (v1.1.0) together with the project:

```
git clone --recursive git@192.168.80.36:Serica/sniper-ebpf.git
```

## Build

This will build libbpf and the demo code.

Note: the environment should be able to run `bpftool` and supports BTF, e.g. Ubuntu 22.10.

Need a newer compiler (e.g., gcc 12.0, clang 15.0).

```
make clean && make all
```

## Debug

See the output from `bpf_printk`:

```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

See the eBPF program / map status:

```
bpftool prog
bpftool map
```

## Run

```
sudo ./sniper-ebpf
```

Use `Ctrl + C` to stop the program.
