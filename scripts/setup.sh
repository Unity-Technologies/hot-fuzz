#! /bin/bash

cd "$(dirname "$0")"

echo -n "checking dependencies ... "

if ! [ -x "$(command -v python3.6)" ]; then
    echo "python3.6 is required"
    exit 1
fi

if ! [ -x "$(command -v pip3.6)" ]; then
    echo "pip3.6 is required"
    exit 1
fi

echo "done"

testhooktype="pre-push"
testhook="../.git/hooks/$testhooktype"
testcmd="PYTHONPATH=$(pwd) VERBOSE=1 make test"

echo -n "setting $testhooktype hook for python unit tests ... "

echo "#!/bin/bash" > $testhook
echo $testcmd >> $testhook
chmod +x $testhook

echo "done"

echo -n "setting up radamsa fuzzer ... "

radamsa_dir=../util/radamsa

if ! [ -d ./$radamsa_dir/.git ]; then
  git submodule update --init
fi

# Build radamsa
make -s -C ./$radamsa_dir

if [ $? -ne 0 ]; then
    echo "failed to build radamsa"
    exit 1
fi

echo "done"
