#! /bin/bash

PYTHON=${PYTHON:=python3}
PIP=${PIP:=pip3}
REQUIREMENTS=requirements.txt

####################################
# Usage
### source run_venv.sh
# or
### ./run_venv.sh activate
# or
### ./run_venv.sh setup_virtualenv
####################################

function setup_virtualenv {
    echo -n "starting up virtual environment ... "
    virtualenv -q -p $(which $PYTHON) --no-site-packages --distribute .env
    echo "done"
}

# Usage:
## source activate_venv.sh activate
function activate {
    source .env/bin/activate
}

function install {
    echo -n "installing requirements to virtual environment ... "
    if [ -f $REQUIREMENTS ]; then
        $PIP install -q -r $REQUIREMENTS
    fi
    echo "done"
}


# Bash magic to call functions defined here from the CLI e.g.
## ./activate_venv.sh activate
"$@"

if [ -z "$1" ]; then
    setup_virtualenv
    activate
    install
fi
