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

pip3 show -q virtualenv
if [ $? -ne 0 ]; then
    pip3 install virtualenv
fi

linter="pycodestyle"
options="--ignore=E501,E124 --show-source --exclude=.env"
lintcmd="$linter $options $(cd .. ; pwd)"

linthooktype="pre-commit"
linthook="../.git/hooks/$linthooktype"

# pylint pre-commit hook on git
echo -n "setting up $linthooktype hook for python git-pylint-commit-hook and $linter... "

echo "#!/bin/bash" > $linthook
echo "./run_venv.sh setup_virtualenv" >> $linthook
echo "source .env/bin/activate" >>  $linthook
echo "./run_venv.sh install" >> $linthook
echo $lintcmd >> $linthook
echo "git-pylint-commit-hook --limit 10 --pylintrc $(cd .. ; pwd)/pylintrc" >> $linthook

echo "done"

echo -n "setting execute bit for $linthook ..."
chmod +x $linthook

echo "done"

testhooktype="pre-push"
testhook="../.git/hooks/$testhooktype"
testcmd="PYTHONPATH=$(pwd) VERBOSE=1 make test"

echo -n "setting $testhooktype hook for python unit tests ... "

echo "#!/bin/bash" > $testhook
echo "./run_venv.sh setup_virtualenv" >> $testhook
echo "source .env/bin/activate" >> $testhook
echo "./run_venv.sh install" >> $testhook
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
