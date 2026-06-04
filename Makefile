# b64-k8s-secrets-tool
#
# Uses a venv built from a Homebrew Python (Tcl/Tk 9) because macOS system Tk 8.5
# renders the dark theme incorrectly.

# Python with a modern Tcl/Tk 9 (from `brew install python-tk@3.13`).
# Falls back to plain python3 if the Homebrew one isn't present.
PYTHON := $(shell [ -x /opt/homebrew/bin/python3.13 ] && echo /opt/homebrew/bin/python3.13 || command -v python3)
VENV   := .venv
PY     := $(VENV)/bin/python
PIP    := $(VENV)/bin/pip
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

## bootstrap: full fresh-install setup (Homebrew Tk + venv + deps)
bootstrap: deps setup
	@echo "Bootstrap complete — run 'make start'"

## deps: install the modern Tcl/Tk for Python via Homebrew (macOS)
deps:
	@command -v brew >/dev/null 2>&1 || { echo "Homebrew not found — install from https://brew.sh"; exit 1; }
	brew list python-tk@3.13 >/dev/null 2>&1 || brew install python-tk@3.13

## setup: create the venv and install Python dependencies (idempotent)
setup: $(VENV)/.installed

$(VENV)/.installed:
	@echo "Creating venv with $(PYTHON)"
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip pyyaml
	@touch $@

## clean: remove the venv, pidfile and bytecode cache
clean: stop
	rm -rf $(VENV) __pycache__ $(PIDFILE)
