CC       := gcc
CFLAGS   := -Wall -Wextra -std=gnu11 -g -Isrc
LDLIBS   := -lpcap -lm

SRC_DIR  := src
BUILD_DIR:= build
BIN      := netsentry

SRCS     := $(wildcard $(SRC_DIR)/*.c)
OBJS     := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all clean run

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Live capture needs raw socket access -> run with sudo, or grant the
# binary CAP_NET_RAW/CAP_NET_ADMIN with setcap instead of using sudo:
#   sudo setcap cap_net_raw,cap_net_admin+eip ./netsentry
run: all
	sudo ./$(BIN) $(ARGS)

clean:
	rm -rf $(BUILD_DIR) $(BIN)
