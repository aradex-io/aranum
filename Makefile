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
	@printf "  make data-audit   — warn when embedded offline datasets look stale\n"
	@printf "  make install      — chmod +x entrypoints + symlink aranum into ~/.local/bin\n"
	@printf "  make clean        — remove __pycache__ / .pyc / stale tmp dirs\n"
	@printf "  make help         — this message\n"

.PHONY: data-audit
data-audit:
	@# Warn when an embedded offline dataset's `updated` date is stale.
	@# Provenance index: aranumtoolkit/docs/DATA-SOURCES.md.
	python3 aranumtoolkit/tests/data_audit.py

.PHONY: install
install:
	@# Make the entrypoints executable and expose `aranum` on PATH. Core is
	@# stdlib-only; optional python deps: pip install -r requirements-optional.txt
	@# Skip _*-prefixed files — they are sourced libraries, not entrypoints.
	@chmod +x aranum.py deps-check.sh 2>/dev/null || true
	@find aranumtoolkit/network standalones -name '*.sh' -not -name '_*' -exec chmod +x {} + 2>/dev/null || true
	@mkdir -p "$$HOME/.local/bin"
	@ln -sf "$$(pwd)/aranum.py" "$$HOME/.local/bin/aranum"
	@printf "Linked %s/aranum -> %s/aranum.py\n" "$$HOME/.local/bin" "$$(pwd)"
	@printf "Ensure ~/.local/bin is on PATH, then: aranum version\n"

.PHONY: test
test: lint unittest pytest smoke

.PHONY: lint
lint:
	@# Lint every tracked .sh via `git ls-files` so a new standalones/<svc>/ dir
	@# can't silently escape linting (the smoke.sh syntax gate already uses a
	@# dynamic find, so this keeps lint and syntax on the same file set).
	@# SC1091 — source-file not findable from CLI (covered by tests/smoke.sh syntax + harness).
	@# SC2046 — word-splitting from command substitution. The dispatcher fleet
	@#         relies on this for the curl_proxy_arg / curl_ua / throttle_nmap_args
	@#         helpers in aranumtoolkit/network/_lib.sh, which intentionally emit 0-or-2 args
	@#         via $(helper). Refactor to bash arrays is tracked separately
	@#         (deferred — see CHANGELOG).
	@# When shellcheck is absent (e.g. an offline box) DEGRADE to a `bash -n`
	@# syntax sweep instead of hard-failing, so `make test` stays green offline.
	@if command -v shellcheck >/dev/null 2>&1; then \
	    printf "Running shellcheck -S warning -e SC1091,SC2046 across every tracked .sh ...\n"; \
	    git ls-files '*.sh' | xargs -r shellcheck -S warning -e SC1091 -e SC2046 -f gcc; \
	else \
	    printf "shellcheck not installed — SKIPPING shellcheck lint.\n"; \
	    printf "  This is expected on an offline box. Install to enable full lint:\n"; \
	    printf "    pip install shellcheck-py\n"; \
	    printf "    sudo dnf install ShellCheck     (Fedora)\n"; \
	    printf "    sudo apt-get install shellcheck (Debian/Ubuntu)\n"; \
	    printf "  Falling back to 'bash -n' syntax check on every tracked .sh ...\n"; \
	    fail=0; \
	    for f in $$(git ls-files '*.sh'); do \
	        bash -n "$$f" || { printf "  SYNTAX FAIL: %s\n" "$$f"; fail=1; }; \
	    done; \
	    if [ "$$fail" -eq 0 ]; then printf "  bash -n: all tracked .sh parse cleanly.\n"; fi; \
	    exit $$fail; \
	fi

.PHONY: unittest
unittest:
	python3 -m unittest discover -s aranumtoolkit/tests -p 'test_*.py' -v

.PHONY: pytest
pytest:
	@# pytest-style tests (tmp_path fixtures, subtests) that unittest-discover
	@# can't collect: the ADR-006 bulk-enum / ssh-triage / ssh-key-triage /
	@# thick-client regression suites. Degrades gracefully when pytest is absent
	@# (offline box) — the unittest target still covers the TestCase suite.
	@if python3 -c 'import pytest' 2>/dev/null; then \
	    python3 -m pytest aranumtoolkit/tests/ -q; \
	else \
	    printf "pytest not installed — SKIPPING pytest-only tests (pip install pytest).\n"; \
	    printf "  The unittest target still covers the TestCase suite.\n"; \
	fi

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
