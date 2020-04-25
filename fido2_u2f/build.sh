#!/bin/bash

mkdir -p build/
for py in *.py; do
  if [ $py == "main.py" ] || [ $py == "boot.py" ]; then
    continue
  fi
  ../adapted-circuitpython/mpy-cross/mpy-cross $py
done
