.PHONY: help install test lint format type-check coverage run clean

help:
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make test       - Run tests"
	@echo "  make lint       - Run linter"
	@echo "  make format     - Format code"
	@echo "  make type-check - Run type checking"
	@echo "  make coverage   - Run tests with coverage"
	@echo "  make run        - Run the analyzer"
	@echo "  make clean      - Clean up"

install:
	uv pip install -e ".[dev]"
	pre-commit install

test:
	pytest

lint:
	flake8 src

format:
	black src tests
	isort src tests

type-check:
	mypy src

coverage:
	pytest --cov=src --cov-report=html --cov-report=term

run:
	python -m log_analyzer --config config.json

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .coverage htmlcov .pytest_cache .mypy_cache
