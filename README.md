# netmon

A CLI to monitor networks and track connection states, made with eBPF.

![preview screenshot](./assets/screenshot.png)

---

# Technical Aspects

- Used a hashmap in the kernel (`BPF_MAP_TYPE_HASH`) to track multiple connections with the same ports and addresses (identified uniquely by the 4-tuple (source_address, destination_address, source_port, destination_port)), thus reducing clutter in the TUI output.
- Tracked two hooks/events, `tcp/tcp_probe` for detecting connections, and `sock/inet_sock_set_state` to track and update state changes for connections.
- Used `bpftool` to auto-generate `vmlinux.h` (for BPF types and functions) and `monitor.skel.h` (helper skeleton for BPF object).

---

# Run It Yourself

## Prerequisites

- `clang`
- `gcc`
- `make`
- `llvm`
- `libbpf`
- `bpftool`
- Linux kernel with BTF enabled

## Build

```sh
# Build header files (vmlinux.h, monitor.skel.h) and binary (netmon)
make

# Add binary to path
mv ./netmon ~/.local/bin/
# or
mv ./netmon /usr/bin/

# Remove all build files
make clean
```

---

# License

GPL 3.0
