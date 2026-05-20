# Build the Redis system-exec module as a shared library.
# Requires gcc + make. redismodule.h and system.so are CHECKED IN for offline use.
#
# Default: `make` is a no-op if system.so is already present (offline-safe).
# To rebuild from source: `make rebuild`
# To refresh the header from upstream: `make refresh-header`

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -fPIC -std=c99 -shared
TARGET  := system.so
SRC     := system.c
HEADER  := redismodule.h
REDIS_TAG ?= 7.4.0
HEADER_URL := https://raw.githubusercontent.com/redis/redis/$(REDIS_TAG)/src/redismodule.h

all: $(TARGET)

# Build only if .so is missing OR source/header is newer. Never reaches the network
# unless someone explicitly invokes `refresh-header`.
$(TARGET): $(SRC) $(HEADER)
	$(CC) $(CFLAGS) -o $@ $(SRC)
	@echo "[+] Built $@ ($$(stat -c%s $@) bytes)"

# Header is checked in. If it's missing, fall back to a network fetch.
$(HEADER):
	@if [ -f "$@" ]; then \
		echo "[+] Using checked-in $@"; \
	else \
		echo "[!] $@ missing — fetching from $(HEADER_URL)"; \
		if command -v curl >/dev/null; then \
			curl -fsSL "$(HEADER_URL)" -o "$@"; \
		elif command -v wget >/dev/null; then \
			wget -qO "$@" "$(HEADER_URL)"; \
		else \
			echo "ERROR: need curl or wget to fetch $(HEADER)"; exit 1; \
		fi; \
	fi

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
# Use `distclean` for a full reset (will require network on next build).
clean:
	rm -f $(TARGET)

distclean: clean
	rm -f $(HEADER)

.PHONY: all clean distclean rebuild refresh-header
