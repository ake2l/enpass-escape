.DEFAULT_GOAL := help

PYTHON ?= python
TARGET ?= apple
DUPLICATES ?= newest

.PHONY: help install test lint format format-check typecheck check build dry-run export

help:
	@echo "install       Install package and development tools"
	@echo "check         Run lint, format check, type check, and tests"
	@echo "format        Format Python files"
	@echo "build         Build wheel and source distribution"
	@echo "dry-run       Analyze INPUT (optional: TARGET, DUPLICATES)"
	@echo "export        Convert INPUT to OUTPUT (optional: TARGET, DUPLICATES)"

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m ruff check .

format:
	$(PYTHON) -m ruff format .

format-check:
	$(PYTHON) -m ruff format --check .

typecheck:
	$(PYTHON) -m mypy enpass_escape tests

check: lint format-check typecheck test

build:
	$(PYTHON) -m build

dry-run:
	@test -n "$(INPUT)" || (echo "INPUT is required"; exit 2)
	$(PYTHON) -m enpass_escape.cli "$(INPUT)" --target "$(TARGET)" --duplicates "$(DUPLICATES)" --dry-run

export:
	@test -n "$(INPUT)" || (echo "INPUT is required"; exit 2)
	@test -n "$(OUTPUT)" || (echo "OUTPUT is required"; exit 2)
	$(PYTHON) -m enpass_escape.cli "$(INPUT)" "$(OUTPUT)" --target "$(TARGET)" --duplicates "$(DUPLICATES)"
