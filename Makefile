# Makefile — convenience targets for aranum (G.4 of iteration G).
# All targets are POSIX-make + bash; no GNU-extensions assumed beyond `.PHONY`.

SHELL := /usr/bin/env bash

# Default — show what's available
.PHONY: help
help:
	@printf "aranum — make targets\n\n"
	@printf "  make test         — full test pass: lint + unittest + smoke\n"
	@printf "  make lint         — shellcheck -S warning across every .sh\n"
	@printf "  make unittest     — python3 -m unittest discover aranumtoolkit/tests/\n"
	@printf "  make smoke        — aranumtoolkit/tests/smoke.sh (syntax + dispatch + gates + tags)\n"
	@printf "  make deps-check   — deps-check.sh — verify enumeration tooling\n"
	@printf "  make install      — chmod +x entrypoints + symlink aranum into ~/.local/bin\n"
	@printf "  make clean        — remove __pycache__ / .pyc / stale tmp dirs\n"
	@printf "  make help         — this message\n"

.PHONY: install
install:
	@# Make the entrypoints executable and expose `aranum` on PATH. Core is
	@# stdlib-only; optional python deps: pip install -r requirements-optional.txt
	@chmod +x aranum.py deps-check.sh aranumtoolkit/network/*.sh standalones/*/*.sh 2>/dev/null || true
	@mkdir -p "$$HOME/.local/bin"
	@ln -sf "$$(pwd)/aranum.py" "$$HOME/.local/bin/aranum"
	@printf "Linked %s/aranum -> %s/aranum.py\n" "$$HOME/.local/bin" "$$(pwd)"
	@printf "Ensure ~/.local/bin is on PATH, then: aranum version\n"

.PHONY: test
test: lint unittest smoke

.PHONY: lint
lint:
	@command -v shellcheck >/dev/null 2>&1 || { \
	    printf "shellcheck not installed. Either:\n"; \
	    printf "  pip install shellcheck-py\n"; \
	    printf "  sudo dnf install ShellCheck     (Fedora)\n"; \
	    printf "  sudo apt-get install shellcheck (Debian/Ubuntu)\n"; \
	    exit 1; }
	@printf "Running shellcheck -S warning -e SC1091,SC2046 across every tracked .sh ...\n"
	@# SC1091 — source-file not findable from CLI (covered by tests/smoke.sh syntax + harness).
	@# SC2046 — word-splitting from command substitution. The dispatcher fleet
	@#         relies on this for the curl_proxy_arg / curl_ua / throttle_nmap_args
	@#         helpers in aranumtoolkit/network/_lib.sh, which intentionally emit 0-or-2 args
	@#         via $(helper). Refactor to bash arrays is tracked separately
	@#         (deferred to v0.32.0 — see CHANGELOG).
	@# Lint every tracked .sh via `git ls-files` so a new standalones/<svc>/ dir
	@# can't silently escape shellcheck (the smoke.sh syntax gate already uses a
	@# dynamic find, so this keeps lint and syntax on the same file set).
	git ls-files '*.sh' | xargs -r shellcheck -S warning -e SC1091 -e SC2046 -f gcc

.PHONY: unittest
unittest:
	python3 -m unittest discover -s aranumtoolkit/tests -p 'test_*.py' -v

.PHONY: smoke
smoke:
	bash aranumtoolkit/tests/smoke.sh

.PHONY: deps-check
deps-check:
	bash deps-check.sh

.PHONY: clean
clean:
	find . -type d -name __pycache__ -not -path './.git/*' -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -not -path './.git/*' -delete 2>/dev/null || true
	rm -rf /tmp/aratool-throttle.* /tmp/aratool-throttle-x.* /tmp/throttle-dryrun*
