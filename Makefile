.PHONY: install test lint build verify integration

install:
	python -m pip install -e ".[dev]"

test:
	python -m pytest -m "not integration"

lint:
	python -m ruff check src tests

build:
	python -m hostium_waf package build --version 1.0.0 --engine 2.9.15

verify: build
	python -m hostium_waf package verify --zip dist/hostium-1.0.0.zip --metadata dist/meta_hostium.yaml

integration:
	python -m pytest -m integration --override-ini="addopts="
