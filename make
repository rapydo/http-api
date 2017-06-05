#!/bin/bash

# dev="-r testpypi"
dev=""

# pandoc --from=markdown --to=rst \
# 	--output=README.rst README.md

python3.6 setup.py sdist

version=$(ls -1rt dist | tail -n 1)
twine register dist/$version $dev
twine upload dist/$version $dev

git add *
git commit -m "releasing $version"
git push
