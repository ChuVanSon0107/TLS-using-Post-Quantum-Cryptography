CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
CPPFLAGS += -Iinclude $(shell pkg-config --cflags liboqs)
LDLIBS += $(shell pkg-config --libs liboqs openssl)

BUILD_DIR := build
COMMON_SRCS := src/common.c src/aes_gcm.c src/kdf.c src/sig_utils.c src/tls_handshake.c src/tls_transcript.c src/tls_finished.c src/tls_record.c src/tls_key_schedule.c

.PHONY: all clean

all: $(BUILD_DIR)/secure_server $(BUILD_DIR)/secure_client

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/secure_server: network/secure_server.c $(COMMON_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@ $(LDLIBS)

$(BUILD_DIR)/secure_client: network/secure_client.c $(COMMON_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -rf $(BUILD_DIR)
