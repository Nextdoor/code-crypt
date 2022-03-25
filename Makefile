ROOT_DIR      := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
VENV_CMD      := python3 -m venv
VENV_DIR      := $(ROOT_DIR)/.venv
VENV_BIN      := $(VENV_DIR)/bin
ISORT_BIN     := $(VENV_BIN)/isort
PYBLACK_BIN   := $(VENV_BIN)/black
PYTEST        := $(VENV_BIN)/pytest

DRY ?= true
ifeq ($(DRY),false)
  ISORT := $(ISORT_BIN)
  PYBLACK := $(PYBLACK_BIN)
else
  ISORT := $(ISORT_BIN) --diff --check
  PYBLACK := $(PYBLACK_BIN) --diff --check
endif

lint: venv
	$(ISORT) code_crypt/
	$(PYBLACK) code_crypt/

test: venv
	$(PYTEST)

install:
	python setup.py install

###############################################################################
# Development Environment Setup
###############################################################################
venv: $(VENV_DIR)

$(VENV_BIN)/activate:
	$(VENV_CMD) $(VENV_DIR)

$(VENV_DIR): $(VENV_BIN)/activate requirements.txt requirements.test.txt
	$(VENV_BIN)/python3 -m pip install -U pip && \
	$(VENV_BIN)/pip install -U setuptools wheel && \
	$(VENV_BIN)/pip install -r requirements.test.txt && \
	$(VENV_BIN)/pip install -U -r requirements.txt && \
	touch $(VENV_DIR)

clean:
	find code_crypt -type f -name '*.pyc' -exec rm {} \;
