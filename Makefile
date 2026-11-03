VERSION ?= $(shell python -c "from hostium_waf.crs_vendor import VERSION_RULESET; print(VERSION_RULESET)")

.PHONY: install test lint build verify integration

install:
	python -m pip install -e ".[dev]"

test:
	python -m pytest -m "not integration"

lint:
	python -m ruff check src tests

build:
	python -m hostium_waf package build --version $(VERSION) --engine 2.9.15

verify: build
	python -m hostium_waf package verify --zip dist/hostium-$(VERSION).zip --metadata dist/meta_hostium.yaml

integration:
	python -m pytest -m integration --override-ini="addopts="
