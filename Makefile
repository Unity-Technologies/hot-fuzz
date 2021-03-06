.PHONY: test

setup:
	scripts/setup.sh

test:
	python3 -m unittest fuzz.test.test_fuzzer && python3 -m unittest test.test_cli

docker-build:
	scripts/build.sh

mock-server:
	python3 -m fuzz.test.mockserver
