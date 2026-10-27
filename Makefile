# Dirs
SRC := src
INCLUDE := include

# Tools
CLANG ?= clang
BPFTOOL ?= bpftool

# Targets
BPF_SRC := $(SRC)/monitor.bpf.c
BPF_OBJ := $(SRC)/monitor.bpf.o
BPF_SKEL := $(INCLUDE)/monitor.skel.h
USER_SRC := $(SRC)/monitor.c
USER_BIN := netmon

all: $(USER_BIN)

# Generate vmlinux.h (if doesn't exist)
$(INCLUDE)/vmlinux.h:
	@mkdir -p $(INCLUDE)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile into BPF bytecode
$(BPF_OBJ): $(BPF_SRC) $(INCLUDE)/vmlinux.h
	$(CLANG) -g -O2 -target bpf -c $< -o $@

# Get header file from BPF bytecode
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Compile userspace binary
$(USER_BIN): $(USER_SRC) $(BPF_OBJ) $(BPF_SKEL)
	gcc -Wall -O2 $(USER_SRC) -lbpf -lelf -o $@

clean:
	rm -f $(SRC)/*.o $(USER_BIN)

.PHONY: all clean
