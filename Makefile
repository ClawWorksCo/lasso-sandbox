.PHONY: build test test-all lint clean install install-dev typecheck coverage

build:
	python -m build

test:
	python3 -m pytest tests/ -m "not integration" -q

test-all:
	python3 -m pytest tests/ -q

lint:
	ruff check lasso/
	ruff format --check lasso/

typecheck:
	python3 -m mypy lasso/ --ignore-missing-imports

coverage:
	python3 -m pytest tests/ -m "not integration" -q --cov=lasso --cov-report=html --cov-report=term

clean:
	rm -rf dist/ build/ *.egg-info

install:
	pip install -e .

install-dev:
	pip install -e ".[all,dev]"
