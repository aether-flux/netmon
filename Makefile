# Dirs
SRC := src
INCLUDE := include

# Tools
CLANG ?= clang
BPFTOOL ?= bpftool

# Targets
BPF_SRC := $(SRC)/monitor.bpf.c
BPF_OBJ := $(SRC)/monitor.bpf.o
USER_SRC := $(SRC)/monitor.c
USER_BIN := netmon

all: $(USER_BIN)

# Generate vmlinux.h (if doesn't exist)
$(INCLUDE)/vmlinux.h:
	@mkdir -p $(INCLUDE)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile into BPF bytecode
$(BPF_OBJ): $(BPF_SRC) $(INCLUDE)/vmlinux.h
	$(CLANG) -g -02 -target bpf -c $< -o $@

# Compile userspace binary
$(USER_BIN): $(USER_SRC) $(BPF_OBJ)
	gcc -Wall -02 $(USER_SRC) -lbpf -lelf -o $@

clean:
	rm -f $(SRC)/*.o $(USER_BIN)

.PHONY: all clean
