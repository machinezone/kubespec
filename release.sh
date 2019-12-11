#!/bin/sh
set -euo pipefail

clean() {
    rm -rf dist build *.egg-info
}

clean
trap clean EXIT

python3 -m pip install --upgrade setuptools wheel twine
python3 setup.py sdist bdist_wheel
python3 -m twine upload dist/*.whl
