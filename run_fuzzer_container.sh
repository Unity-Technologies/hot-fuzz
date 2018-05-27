#! /bin/bash

cmdname=$(basename $0)
cmddir="$(dirname $0)"

function usage {
cat << EOF
Usage:
  Run the fuzzer from a docker container

  $cmdname [fuzzer args]
EOF
  exit 1
}

if [ $# -eq 0 ]; then
    usage
fi

fuzz_lib=$( cd ${LIB_DIR:-"fuzz/"}; pwd)

pushd $cmddir

if [ ! -d results ]; then
    mkdir results
fi

identifier=${IMAGE_IDENTIFIER:-`date "+%y-%m-%d.%H%M%S"`}
image=${IMAGE:-"hot-fuzz"}
results="$(pwd)/results/"
fuzzer="$(pwd)/fuzzer.py"

echo "=== Launching fuzzer container"

docker run -e DOCKER=1 -v $results:/hotfuzz/results/ -v $fuzz_lib:/hotfuzz/fuzz/ -v $fuzzer:/hotfuzz/fuzzer.py --rm -t --name=image-${identifier} ${image} python3 fuzzer.py "$@"
success=$?

popd

exit $success
