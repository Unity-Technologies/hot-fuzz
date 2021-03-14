.PHONY: test

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +
	rm -f *.whl

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache

setup:
	scripts/setup.sh

test:
	python3.6 -m unittest fuzz.test.test_fuzzer && python3.6 -m unittest test.test_cli

docker-build: clean
	scripts/build.sh

mock-server:
	python3.6 -m fuzz.test.mockserver

lint: clean
	pip install -U darker isort
	darker --check --diff --revision=origin/master... --isort fuzz test setup.py

lint-apply: clean
	pip install -U darker isort
	darker --revision=origin/master --isort fuzz test setup.py

git-hooks:
	pip install pre-commit
	pre-commit --version
	pre-commit install
