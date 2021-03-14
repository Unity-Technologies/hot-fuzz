.PHONY: test

setup:
	scripts/setup.sh

test:
	python3.6 -m unittest fuzz.test.test_fuzzer && python3.6 -m unittest test.test_cli

docker-build:
	scripts/build.sh

mock-server:
	python3.6 -m fuzz.test.mockserver
