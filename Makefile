# b64-k8s-secrets-tool

UNAME := $(shell uname -s)

# macOS: prefer Homebrew Python (Tcl/Tk 9) because system Tk 8.5 renders the
# dark theme incorrectly. Homebrew lives in /opt/homebrew on Apple Silicon and
# /usr/local on Intel. Linux: plain python3 with Tk 8.6 works fine.
ifeq ($(UNAME), Darwin)
PYTHON := $(shell [ -x /opt/homebrew/bin/python3.13 ] && echo /opt/homebrew/bin/python3.13 || { [ -x /usr/local/bin/python3.13 ] && echo /usr/local/bin/python3.13 || command -v python3; })
else
PYTHON := $(shell command -v python3)
endif

VENV    := .venv
PY      := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
PIDFILE := .app.pid

.PHONY: bootstrap deps start stop restart status setup clean

## start: launch the app in the background
start: setup
	@if [ -f $(PIDFILE) ] && kill -0 `cat $(PIDFILE)` 2>/dev/null; then \
		echo "Already running (PID `cat $(PIDFILE)`)"; \
	else \
		$(PY) app.py & echo $$! > $(PIDFILE); \
		echo "Started (PID `cat $(PIDFILE)`)"; \
	fi

## stop: stop the running app
stop:
	@if [ -f $(PIDFILE) ] && kill -0 `cat $(PIDFILE)` 2>/dev/null; then \
		kill `cat $(PIDFILE)` && echo "Stopped (PID `cat $(PIDFILE)`)"; \
		rm -f $(PIDFILE); \
	else \
		echo "Not running"; rm -f $(PIDFILE); \
	fi

## restart: stop then start
restart: stop start

## status: show whether the app is running
status:
	@if [ -f $(PIDFILE) ] && kill -0 `cat $(PIDFILE)` 2>/dev/null; then \
		echo "Running (PID `cat $(PIDFILE)`)"; \
	else \
		echo "Not running"; \
	fi

## bootstrap: full fresh-install setup (system deps + venv)
bootstrap: deps setup
	@echo "Bootstrap complete — run 'make start'"

## deps: install system dependencies (macOS: Homebrew Tk; Linux: apt packages)
deps:
ifeq ($(UNAME), Darwin)
	@command -v brew >/dev/null 2>&1 || { echo "Homebrew not found — install from https://brew.sh"; exit 1; }
	brew list python-tk@3.13 >/dev/null 2>&1 || brew install python-tk@3.13
else
	sudo apt-get install -y python3-tk python3-venv python3-pip
endif

## setup: create the venv and install Python dependencies (idempotent)
setup: $(VENV)/.installed

$(VENV)/.installed: pyproject.toml
	@echo "Creating venv with $(PYTHON)"
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -e '.[dev]'
	@touch $@

## clean: remove the venv, pidfile, build artifacts and tooling caches
clean: stop
	rm -rf $(VENV) $(PIDFILE)
	rm -rf *.egg-info build dist .pytest_cache .ruff_cache _version.py
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
