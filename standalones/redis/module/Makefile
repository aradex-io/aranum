# Build the Redis system-exec module as a shared library.
# Requires a local C compiler + make. Source/header are vendored; system.so is
# intentionally built for the assessment host and is not checked in.
#
# Default and exploit-runtime builds never access the network.
# To rebuild from source: `make rebuild`
# To refresh the header from upstream: `make refresh-header`

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -fPIC -std=c99 -shared
TARGET  := system.so
SRC     := system.c
HEADER  := redismodule.h
REDIS_TAG ?= 7.4.0
HEADER_URL := https://raw.githubusercontent.com/redis/redis/$(REDIS_TAG)/src/redismodule.h

all: verify-source $(TARGET)

# Build only if .so is missing OR source/header is newer. Never reaches the network
# unless someone explicitly invokes `refresh-header`.
$(TARGET): verify-source $(SRC) $(HEADER)
	$(CC) $(CFLAGS) -o $@ $(SRC)
	@echo "[+] Built $@ ($$(stat -c%s $@) bytes)"

# Header is checked in. A missing input fails closed; network refresh is an
# explicit maintainer-only target and is never reachable from `all`.
$(HEADER):
	@echo "ERROR: vendored $(HEADER) is missing; runtime builds never fetch inputs"; exit 1

verify-source:
	@python3 verify_source.py

rebuild:
	rm -f $(TARGET)
	$(MAKE) $(TARGET)

refresh-header:
	@echo "[+] Refreshing $(HEADER) from $(HEADER_URL)"
	@if command -v curl >/dev/null; then \
		curl -fsSL "$(HEADER_URL)" -o "$(HEADER)"; \
	elif command -v wget >/dev/null; then \
		wget -qO "$(HEADER)" "$(HEADER_URL)"; \
	else \
		echo "ERROR: need curl or wget"; exit 1; \
	fi

# `clean` only removes the build artifact, NOT the checked-in header.
# `distclean` is maintainer-only; default builds then fail until the vendored
# header is explicitly restored and its SOURCE.json checksum is updated.
clean:
	rm -f $(TARGET)

distclean: clean
	rm -f $(HEADER)

.PHONY: all clean distclean rebuild refresh-header verify-source
