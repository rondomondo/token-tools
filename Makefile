 # Project Configuration

PROJECT := jwt_verify
VERSION := 3.12
SHELL := /bin/bash
VENV := .venv
SOURCE := $(shell which source)
PYTEST := $(shell which pytest)
PYTHON := $(shell which python3)
PIP := $(shell which pip3)
GCC := $(shell which gcc)
PYCODESTYLE := $(shell which pycodestyle)
REQUIREMENTS := requirements.txt
MAIN_SCRIPT := jwt_verify.py
LINE_LENGTH := 119


.PHONY: help build venv install format lint style sanity clean

help:  ## Display this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

build: ## run build precursers
	./build.sh 

venv:  ## Create a virtual environment
	@if [ ! -d "$(VENV)" ]; then \
		$(PYTHON) -m venv $(VENV); \
		echo "Virtual environment created at $(VENV)"; \
	else \
		echo "Virtual environment already exists at $(VENV)"; \
	fi


install: venv ## Install dependencies
	@if [ "$$(uname)" = "Linux" ]; then \
		sudo apt-get update; \
		sudo apt-get install pip gcc zlib1g-dev -y; \
	fi
#	GCC = $(shell which gcc)
	$(shell which pip3) install -r $(REQUIREMENTS)

format: install ## Format code using black (install black first)
	$(PYTHON) -m autopep8 --max-line-length  $(LINE_LENGTH) --in-place --aggressive $(MAIN_SCRIPT)

style: install ## Format code using black
	$(PYCODESTYLE) --statistics  --max-line-length $(LINE_LENGTH) --max-doc-length $(LINE_LENGTH) $(MAIN_SCRIPT)

lint: install## Lint code using flake8
	$(PYTHON) -m flake8   --max-line-length $(LINE_LENGTH) --max-doc-length $(LINE_LENGTH) $(MAIN_SCRIPT) 


clean:  ## Clean up generated files and directories
	@rm -rf $(VENV) __pycache__ *.pyc temp/

